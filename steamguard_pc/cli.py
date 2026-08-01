import argparse
import tomllib
import difflib
import json
import getpass
import re
import os
import sys
import time
from dataclasses import replace
from importlib import metadata as importlib_metadata
from pathlib import Path
import requests

from . import auth, backup, confirmations, enrollment, mafile, operation_lock, session, steam_time, storage
from .auth import GuardAction, LoginResult, SteamAuthError
from .confirmations import Confirmation, ConfirmationError
from .crypto import generate_device_id, seconds_remaining, steam_totp
from .enrollment import EnrollmentError
from .session import SessionExpiredError
from .storage import SecretStorageUnavailable

STEAM_LOGIN_SECURE_ENV_VAR = "STEAMGUARD_PC_STEAM_LOGIN_SECURE"
SESSIONID_ENV_VAR = "STEAMGUARD_PC_SESSIONID"


EXPECTED_ERRORS = (
    ValueError,
    KeyError,
    backup.BackupError,
    SecretStorageUnavailable,
    SessionExpiredError,
    ConfirmationError,
    SteamAuthError,
    EnrollmentError,
    operation_lock.OperationLockError,
)


COOKIE_GUIDE = """
How to copy Steam Community cookies:
1. Open https://steamcommunity.com and sign in.
2. Press F12, then open Application > Storage > Cookies > https://steamcommunity.com.
3. Copy only these cookie values into this app when prompted:
   - steamLoginSecure
   - sessionid
Treat both values like passwords. Do not paste them into chat, logs, screenshots, or issue reports.
"""


ANSI_RESET = "\033[0m"
COLOR_HEADING = "1;36"
COLOR_INFO = "36"
COLOR_SUCCESS = "32"
COLOR_WARNING = "33"
COLOR_ERROR = "1;31"
COLOR_INTERRUPT = "1;33"
COLOR_LABEL = "1"
COLOR_VALUE = "1;36"
COLOR_MUTED = "2"
COLOR_MODES = {"auto", "always", "never"}
_COLOR_MODE: str | None = None


def _argv_color_mode(argv: list[str] | None) -> str | None:
    arguments = sys.argv[1:] if argv is None else argv
    for index, argument in enumerate(arguments):
        if argument == "--no-color":
            return "never"
        if argument == "--color" and index + 1 < len(arguments) and arguments[index + 1] in COLOR_MODES:
            return arguments[index + 1]
        if argument.startswith("--color="):
            value = argument.split("=", 1)[1]
            if value in COLOR_MODES:
                return value
    return None




def _color_enabled(stream) -> bool:
    if _COLOR_MODE == "never":
        return False
    if _COLOR_MODE == "always":
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    forced = os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE")
    if forced and forced != "0":
        return True
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _color(text: str, code: str, stream) -> str:
    if not _color_enabled(stream):
        return text
    return f"\033[{code}m{text}{ANSI_RESET}"


def _info(text: str) -> str:
    return _color(text, COLOR_INFO, sys.stdout)


def _success(text: str) -> str:
    return _color(text, COLOR_SUCCESS, sys.stdout)


def _warning(text: str, stream=None) -> str:
    target = sys.stdout if stream is None else stream
    return _color(text, COLOR_WARNING, target)


def _danger(text: str) -> str:
    return _color(text, COLOR_ERROR, sys.stdout)


def _label(text: str) -> str:
    return _color(text, COLOR_LABEL, sys.stdout)


def _value(text: str) -> str:
    return _color(text, COLOR_VALUE, sys.stdout)


def _muted(text: str) -> str:
    return _color(text, COLOR_MUTED, sys.stdout)


def _prompt(text: str) -> str:
    return _color(text, COLOR_LABEL, sys.stdout)


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=36, width=100, **kwargs)

    def start_section(self, heading: str | None) -> None:
        if heading is not None:
            heading = _color(heading, COLOR_HEADING, sys.stdout)
        super().start_section(heading)


def _version_from_pyproject() -> str | None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.is_file():
        return None
    try:
        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    version = project.get("version")
    return version if isinstance(version, str) and version else None


def _package_version() -> str:
    pyproject_version = _version_from_pyproject()
    if pyproject_version is not None:
        return pyproject_version
    try:
        return importlib_metadata.version("steamguard-pc")
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


def _invalid_choice_suggestion(parser: argparse.ArgumentParser, message: str) -> str | None:
    match = re.search(r"invalid choice: '([^']+)'", message)
    if match is None:
        return None

    invalid_value = match.group(1)
    choices: list[str] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            choices.extend(str(choice) for choice in action.choices)
        elif action.choices is not None:
            choices.extend(str(choice) for choice in action.choices)

    matches = difflib.get_close_matches(invalid_value, choices, n=1, cutoff=0.55)
    return matches[0] if matches else None


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        suggestion = _invalid_choice_suggestion(self, message)
        if suggestion is not None:
            message = f"{message}\nDid you mean '{suggestion}'?"
        self.print_usage(sys.stderr)
        self.exit(2, f"{_color(f'{self.prog}: error:', COLOR_ERROR, sys.stderr)} {message}\n")


HELP_DESCRIPTION = None


HELP_EPILOG = None


def _summary_text(summary: str | list[str] | None) -> str:
    if summary is None:
        return "-"
    if isinstance(summary, list):
        return "; ".join(str(item) for item in summary) if summary else "-"
    return summary or "-"


def _confirmation_type(confirmation: Confirmation) -> str:
    value = confirmation.type_name if confirmation.type_name is not None else confirmation.type
    return str(value) if value is not None else "-"

KNOWN_BATCH_APPROVAL_TYPES = {2, 3, "2", "3"}
KNOWN_BATCH_APPROVAL_LABELS = {"trade", "market", "market listing", "marketlisting"}
_AUTH_PLATFORM_LABELS = {1: "Steam client", 2: "Web browser", 3: "Mobile app"}
_SESSION_PERSISTENCE_LABELS = {-1: "Invalid", 0: "Ephemeral", 1: "Persistent"}
_SECURITY_HISTORY_LABELS = {1: "Used previously", 2: "No prior history"}



def _confirmation_is_safe_for_batch_approval(confirmation: Confirmation) -> bool:
    if confirmation.type in KNOWN_BATCH_APPROVAL_TYPES or str(confirmation.type) in KNOWN_BATCH_APPROVAL_TYPES:
        return True
    labels = {
        str(value).replace("_", " ").casefold()
        for value in (confirmation.type_name, confirmation.type)
        if value is not None
    }
    compact_labels = {label.replace(" ", "") for label in labels}
    return bool(labels & KNOWN_BATCH_APPROVAL_LABELS or compact_labels & KNOWN_BATCH_APPROVAL_LABELS)


def _unsafe_batch_approval_confirmations(confirmations_to_review: list[Confirmation]) -> list[Confirmation]:
    return [item for item in confirmations_to_review if not _confirmation_is_safe_for_batch_approval(item)]

def _account_label(metadata: storage.AccountMetadata) -> str:
    return f"{metadata.account_name} ({metadata.steamid64})" if metadata.account_name else metadata.steamid64


def _print_confirmation_row(confirmation: Confirmation) -> None:
    print(
        "\t".join(
            [
                _value(confirmation.id),
                _confirmation_type(confirmation),
                confirmation.creator_id or "-",
                confirmation.headline or "-",
                _summary_text(confirmation.summary),
            ]
        )
    )


def _print_confirmation_detail(confirmation: Confirmation, account_label: str | None = None) -> None:
    if account_label is not None:
        print(f"{_label('account:')} {account_label}")
    print(f"{_label('id:')} {_value(confirmation.id)}")
    print(f"{_label('type:')} {_confirmation_type(confirmation)}")
    print(f"{_label('creator_id:')} {confirmation.creator_id or '-'}")
    print(f"{_label('headline:')} {confirmation.headline or '-'}")
    print(f"{_label('summary:')} {_summary_text(confirmation.summary)}")

def _parse_client_id(value: str) -> int:
    if not value.isdecimal():
        raise ValueError("CLIENT_ID must be a positive unsigned integer")
    client_id = int(value)
    if not 1 <= client_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("CLIENT_ID must be a positive unsigned integer")
    return client_id


def _login_location_text(confirmation: auth.LoginConfirmation) -> str:
    parts = [
        part
        for part in (confirmation.city, confirmation.state, confirmation.country)
        if part
    ]
    if parts:
        return ", ".join(parts)
    return confirmation.geoloc or "-"


def _login_platform_text(value: int | None) -> str:
    if value is None:
        return "-"
    return _AUTH_PLATFORM_LABELS.get(value, str(value))


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _print_login_confirmation_row(confirmation: auth.LoginConfirmation) -> None:
    print(
        "\t".join(
            [
                _value(str(confirmation.client_id)),
                confirmation.ip or "-",
                _login_location_text(confirmation),
                _login_platform_text(confirmation.platform_type),
                confirmation.device_friendly_name or "-",
            ]
        )
    )


def _login_history_text(value: int | None) -> str:
    if value is None:
        return "-"
    return _SECURITY_HISTORY_LABELS.get(value, str(value))


def _requested_persistence_text(value: int | None) -> str:
    if value is None:
        return "-"
    return _SESSION_PERSISTENCE_LABELS.get(value, str(value))


def _print_login_confirmation_detail(metadata: storage.AccountMetadata, confirmation: auth.LoginConfirmation) -> None:
    print(f"{_label('account:')} {_account_label(metadata)}")
    print(f"{_label('client_id:')} {_value(str(confirmation.client_id))}")
    print(f"{_label('ip:')} {confirmation.ip or '-'}")
    print(f"{_label('location:')} {_login_location_text(confirmation)}")
    print(f"{_label('geoloc:')} {confirmation.geoloc or '-'}")
    print(f"{_label('platform:')} {_login_platform_text(confirmation.platform_type)}")
    print(f"{_label('device:')} {confirmation.device_friendly_name or '-'}")
    print(f"{_label('login_history:')} {_login_history_text(confirmation.login_history)}")
    print(f"{_label('requested_persistence:')} {_requested_persistence_text(confirmation.requested_persistence)}")
    print(f"{_label('location_mismatch:')} {_yes_no(confirmation.location_mismatch)}")
    print(f"{_label('high_usage_login:')} {_yes_no(confirmation.high_usage_login)}")


def _print_trade_offer_id(
    community_session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret: str,
    confirmation_id: str,
) -> None:
    try:
        html = confirmations.get_confirmation_details_html(
            community_session,
            steamid64,
            device_id,
            identity_secret,
            confirmation_id,
        )
        trade_offer_id = confirmations.trade_offer_id_from_details_html(html)
    except (ConfirmationError, steam_time.SteamTimeError):
        trade_offer_id = None
    print(f"{_label('trade_offer_id:')} {trade_offer_id or 'unavailable'}")

def _print_batch_confirmation_review(
    metadata: storage.AccountMetadata,
    community_session: requests.Session,
    identity_secret: str,
    confirmations_to_review: list[Confirmation],
) -> None:
    account_label = _account_label(metadata)
    count = len(confirmations_to_review)
    print(_info(f"Pending confirmations for {account_label}: {count}"))
    for index, confirmation in enumerate(confirmations_to_review, start=1):
        print(_muted(f"--- confirmation {index} of {count} ---"))
        _print_confirmation_detail(confirmation, account_label)
        _print_trade_offer_id(
            community_session,
            metadata.steamid64,
            metadata.device_id or "",
            identity_secret,
            confirmation.id,
        )


def _exception_text(exc: BaseException) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return str(exc)


def _account_metadata(steamid64: str) -> storage.AccountMetadata:
    metadata = storage.load_accounts().get(steamid64)
    if metadata is None:
        raise KeyError(f"missing account metadata for {steamid64}")
    if not metadata.device_id:
        raise KeyError(f"missing device_id for {steamid64}")
    return metadata

def _selected_backup_ids(steamid64s: list[str]) -> list[str]:
    accounts = storage.load_accounts()
    if steamid64s:
        for steamid64 in steamid64s:
            if steamid64 not in accounts:
                raise KeyError(f"missing account metadata for {steamid64}")
        selected_ids = list(steamid64s)
    else:
        selected_ids = sorted(accounts)

    if not selected_ids:
        raise ValueError("no accounts selected for backup")
    return selected_ids


def _confirmation_context(steamid64: str) -> tuple[storage.AccountMetadata, str, requests.Session]:
    metadata = _account_metadata(steamid64)
    identity_secret = storage.get_required_secret(steamid64, "identity_secret")
    community_session = session.get_community_session(steamid64)
    return metadata, identity_secret, community_session


def _login_confirmation_context(steamid64: str) -> tuple[storage.AccountMetadata, str, str, auth.SteamAuthClient]:
    metadata = _account_metadata(steamid64)
    shared_secret = storage.get_required_secret(steamid64, "shared_secret")
    access_token, _ = session.refresh_auth_tokens(steamid64)
    return metadata, shared_secret, access_token, auth.SteamAuthClient()


def _load_current_confirmations(
    steamid64: str,
) -> tuple[storage.AccountMetadata, str, requests.Session, list[Confirmation]]:
    metadata, identity_secret, community_session = _confirmation_context(steamid64)
    try:
        current = confirmations.get_confirmations(
            community_session,
            steamid64,
            metadata.device_id or "",
            identity_secret,
        )
    except confirmations.NeedAuthenticationError:
        community_session = session.refresh_community_session(steamid64)
        current = confirmations.get_confirmations(
            community_session,
            steamid64,
            metadata.device_id or "",
            identity_secret,
        )
    return metadata, identity_secret, community_session, current


def _find_current_confirmation(steamid64: str, confirmation_id: str) -> tuple[storage.AccountMetadata, str, requests.Session, Confirmation]:
    metadata, identity_secret, community_session, current = _load_current_confirmations(steamid64)
    target = next((item for item in current if item.id == confirmation_id), None)
    if target is None:
        raise confirmations.ConfirmationNotFoundError(f"confirmation {confirmation_id} not found")
    return metadata, identity_secret, community_session, target



def _cookie_values_from_env() -> tuple[str | None, str | None]:
    return (
        os.environ.get(STEAM_LOGIN_SECURE_ENV_VAR),
        os.environ.get(SESSIONID_ENV_VAR),
    )


def _print_cookie_guide() -> None:
    print(_info(COOKIE_GUIDE.strip()))


def _import_mafile_path(path: str | Path) -> tuple[mafile.ImportedSteamGuard, storage.AccountMetadata]:
    for warning in mafile.unsafe_import_path_warnings(path):
        print(_warning(f"Warning: {warning}", sys.stderr), file=sys.stderr)

    try:
        imported = mafile.load_mafile(path)
    except mafile.EncryptedMaFileRequiresPasskey:
        passkey = getpass.getpass(_prompt("SDA encryption passkey: "))
        if not passkey:
            raise ValueError("SDA encryption passkey is required")
        try:
            imported = mafile.load_mafile(path, passkey=passkey)
        finally:
            passkey = ""
    metadata = storage.store_imported_guard(imported)
    label = metadata.account_name or metadata.steamid64
    print(_success(f"Imported {label} ({metadata.steamid64})"))
    if imported.revocation_code:
        print(_warning(f"Steam Guard revocation code was stored. Run `steamguard-pc revocation-code {metadata.steamid64}` in a private terminal and store it offline."))
    return imported, metadata


def _select_mafile_path(explicit_path: str | None) -> Path:
    if explicit_path:
        return Path(explicit_path)

    candidates = mafile.find_mafile_candidates()
    if candidates:
        print(_info("Found .maFile candidates:"))
        for index, candidate in enumerate(candidates, start=1):
            print(f"  {_value(str(index))}. {candidate}")
        print(_muted("Choose a number, type another path, or press Enter to cancel."))
        choice = input(_prompt("maFile: ")).strip()
        if not choice:
            raise ValueError("setup cancelled before import")
        if choice.isdecimal():
            selected = int(choice)
            if 1 <= selected <= len(candidates):
                return candidates[selected - 1]
        return Path(choice)

    print(_warning("No .maFile files found in common locations."))
    choice = input(_prompt("Path to .maFile (blank to cancel): ")).strip()
    if not choice:
        raise ValueError("setup cancelled before import")
    return Path(choice)


def _store_cookies_from_env(steamid64: str) -> bool:
    steam_login_secure, sessionid = _cookie_values_from_env()
    if bool(steam_login_secure) != bool(sessionid):
        raise ValueError(
            f"set both {STEAM_LOGIN_SECURE_ENV_VAR} and {SESSIONID_ENV_VAR}, or set neither"
        )
    if not steam_login_secure or not sessionid:
        return False

    session.save_community_cookies(steamid64, steam_login_secure, sessionid)
    print(_success(f"Stored Steam Community cookies for {steamid64} from environment variables."))
    return True


def _setup_cookies(steamid64: str, imported_had_cookies: bool, skip_cookies: bool) -> None:
    if skip_cookies:
        print(_warning("Skipped cookie setup. Run `steamguard-pc cookie-guide` then `steamguard-pc set-cookies` when needed."))
        return

    if _store_cookies_from_env(steamid64):
        return

    if imported_had_cookies:
        print(_success("Steam Community cookies were imported from the .maFile."))
        print(_muted(f"If confirmations fail, refresh them with `steamguard-pc set-cookies {steamid64}`."))
        return

    _print_cookie_guide()
    if input(_prompt("Store Steam Community cookies now? [y/N]: ")).strip().casefold() != "y":
        print(_warning(f"Skipped cookie setup. Run `steamguard-pc set-cookies {steamid64}` before confirmations."))
        return

    steam_login_secure = getpass.getpass(_prompt("steamLoginSecure: "))
    sessionid = getpass.getpass(_prompt("sessionid: "))
    session.save_community_cookies(steamid64, steam_login_secure, sessionid)
    print(_success(f"Stored Steam Community cookies for {steamid64}."))


def _code_for_login(action: GuardAction, auth_session: auth.AuthSession) -> str | None:
    if action.type == auth.GUARD_DEVICE_CODE and auth_session.steamid64:
        shared_secret = storage.get_secret(auth_session.steamid64, "shared_secret")
        if shared_secret:
            print(_info(f"Using stored Steam Guard code for {auth_session.steamid64}."))
            return steam_totp(shared_secret)

    detail = f" ({action.message})" if action.message else ""
    return input(_prompt(f"Steam Guard {action.label}{detail}: ")).strip()


def _wait_for_login_confirmation(actions: list[GuardAction]) -> None:
    labels = ", ".join(action.label for action in actions)
    print(_info(f"Approve the Steam login prompt using: {labels}."))
    input(_prompt("Press Enter after approving it."))


def _login_with_prompts(account_name: str | None = None) -> LoginResult:
    account_name = account_name or input(_prompt("Steam account name: ")).strip()
    if not account_name:
        raise ValueError("Steam account name is required")
    password = getpass.getpass(_prompt("Steam password: "))
    print(_info("Signing in with Steam. Password is sent only to Steam over HTTPS."))
    return auth.SteamAuthClient().login_with_credentials(
        account_name=account_name,
        password=password,
        code_provider=_code_for_login,
        confirmation_provider=_wait_for_login_confirmation,
    )


def _store_login_result(result: LoginResult) -> storage.AccountMetadata:
    storage.put_secret(result.steamid64, "refresh_token", result.refresh_token)
    session.save_access_token(result.steamid64, result.access_token)
    session.save_community_cookies(result.steamid64, result.steam_login_secure, result.sessionid)

    existing = storage.load_accounts().get(result.steamid64)
    metadata = storage.AccountMetadata(
        steamid64=result.steamid64,
        account_name=result.account_name,
        device_id=(existing.device_id if existing else None) or generate_device_id(result.steamid64),
        last_imported_at=existing.last_imported_at if existing else None,
    )
    storage.upsert_account(metadata)
    return metadata


def _login_and_store(account_name: str | None = None) -> tuple[LoginResult, storage.AccountMetadata]:
    result = _login_with_prompts(account_name)
    metadata = _store_login_result(result)
    print(_success(f"Signed in and stored Steam Community session for {metadata.account_name or metadata.steamid64} ({metadata.steamid64})."))
    return result, metadata


def _print_revocation_code(metadata: storage.AccountMetadata, revocation_code: str) -> None:
    label = metadata.account_name or metadata.steamid64
    print(f"{_warning(f'Steam Guard revocation code for {label} ({metadata.steamid64}):')} {revocation_code}")
    print(_warning("Store this code offline. Steam formats it as R followed by five digits, and it can remove this authenticator from the account."))
    print(_muted("This is not the seven-digit recovery code Steam requests during account sign-in recovery."))


def _enroll_with_prompts(account_name: str | None = None) -> storage.AccountMetadata:
    result, metadata = _login_and_store(account_name)
    print(_warning("Adding a new mobile authenticator changes account security state and can affect trade/market holds."))
    phrase = f"ADD AUTHENTICATOR {result.steamid64}"
    if input(_prompt(f"Type {phrase!r} to continue: ")) != phrase:
        raise ValueError("authenticator enrollment cancelled")

    has_linked_phone = input(_prompt("Have you linked a verified SMS-capable phone number to this Steam account? [y/N]: ")).strip().casefold() == "y"
    sms_phone_id = "1" if has_linked_phone else None

    client = enrollment.EnrollmentClient()
    add_result = client.add_authenticator(
        result.access_token,
        result.steamid64,
        account_name=result.account_name,
        device_id=metadata.device_id,
        sms_phone_id=sms_phone_id,
    )

    imported = replace(
        add_result.imported,
        refresh_token=result.refresh_token,
        access_token=result.access_token,
        steam_login_secure=result.steam_login_secure,
        sessionid=result.sessionid,
    )
    metadata = storage.store_imported_guard(imported)
    print(_success("Authenticator secrets were stored before finalization."))
    if imported.revocation_code:
        _print_revocation_code(metadata, imported.revocation_code)
    if has_linked_phone:
        print(_info("Steam should send the activation code by SMS to the linked phone number."))
    else:
        print(_info("Steam may send the activation code by email when it offers the no-phone path."))
    resend_phrase = f"SEND ACTIVATION EMAIL {result.steamid64}"
    print(_muted(f"If no code arrives, type {resend_phrase!r} instead of the code to ask Steam to email another activation code."))
    activation_code = input(_prompt("Steam activation code from email or SMS: ")).strip()
    validate_sms_code = has_linked_phone
    if activation_code == resend_phrase:
        client.send_activation_email(result.access_token, result.steamid64)
        print(_success("Requested an activation-code email from Steam."))
        validate_sms_code = False
        activation_code = input(_prompt("Steam activation code from email or SMS: ")).strip()
    if not activation_code:
        raise ValueError("Steam activation code is required")
    client.finalize_authenticator(
        result.access_token,
        result.steamid64,
        imported.shared_secret,
        activation_code,
        validate_sms_code=validate_sms_code,
    )
    print(_success(f"Authenticator added and finalized for {metadata.account_name or metadata.steamid64} ({metadata.steamid64})."))
    if imported.revocation_code:
        print(_muted(f"Stored revocation code remains available with `steamguard-pc revocation-code {metadata.steamid64}`."))
    return metadata


def _cmd_login(args: argparse.Namespace) -> int:
    _login_and_store(args.account_name)
    return 0


def _cmd_login_confirmations(args: argparse.Namespace) -> int:
    _, _, access_token, client = _login_confirmation_context(args.steamid64)
    current = client.get_login_confirmations(access_token)
    if not current:
        print(_muted("No pending login confirmations."))
        return 0

    for confirmation in current:
        _print_login_confirmation_row(confirmation)
    return 0


def _cmd_respond_login(args: argparse.Namespace, *, confirm: bool) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        client_id = _parse_client_id(args.client_id)
        metadata, shared_secret, access_token, client = _login_confirmation_context(args.steamid64)
        confirmation = client.get_login_confirmation(access_token, client_id)
        _print_login_confirmation_detail(metadata, confirmation)

        action = "APPROVE" if confirm else "DENY"
        noun = "approval" if confirm else "denial"
        expected = f"{action} LOGIN {client_id}"
        if input(_prompt(f"Type {expected!r} to {action.casefold()} this login: ")) != expected:
            print(_warning(f"Login {noun} cancelled."))
            return 1

        client.respond_to_login_confirmation(
            access_token,
            args.steamid64,
            shared_secret,
            confirmation,
            confirm=confirm,
        )
        past_tense = "Approved" if confirm else "Denied"
        print(_success(f"{past_tense} login {client_id}."))
        return 0


def _cmd_approve_login(args: argparse.Namespace) -> int:
    return _cmd_respond_login(args, confirm=True)


def _cmd_deny_login(args: argparse.Namespace) -> int:
    return _cmd_respond_login(args, confirm=False)


def _cmd_enroll(args: argparse.Namespace) -> int:
    _enroll_with_prompts(args.account_name)
    return 0


def _delete_account_with_consent(steamid64: str) -> int:
    with operation_lock.account_operation_lock(steamid64):
        metadata = storage.load_accounts().get(steamid64)
        if metadata is None:
            raise KeyError(f"missing account metadata for {steamid64}")

        label = _account_label(metadata)
        print(_danger(f"Delete stored account {label}?"))
        print(_warning("This removes local steamguard-pc metadata and all stored secrets for this account."))
        print(_muted("This does not remove the authenticator from Steam."))
        expected = f"DELETE ACCOUNT {steamid64}"
        if input(_prompt(f"Type {expected!r} to delete this account: ")) != expected:
            print(_warning("Account deletion cancelled."))
            return 1

        deleted = storage.delete_account(steamid64)
        print(_success(f"Deleted account {_account_label(deleted)}."))
        return 0


def _cmd_accounts(args: argparse.Namespace) -> int:
    if args.delete:
        return _delete_account_with_consent(args.delete)

    accounts = storage.load_accounts()
    sorted_accounts = sorted(accounts.values(), key=lambda account: account.steamid64)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "steamid64": metadata.steamid64,
                        "account_name": metadata.account_name,
                        "device_id": metadata.device_id,
                        "last_imported_at": metadata.last_imported_at,
                    }
                    for metadata in sorted_accounts
                ],
                indent=2,
            )
        )
        return 0

    if not sorted_accounts:
        print(_muted("No accounts imported."))
        return 0

    for metadata in sorted_accounts:
        print(
            "\t".join(
                [
                    _value(metadata.steamid64),
                    metadata.account_name or "-",
                    metadata.device_id or "-",
                ]
            )
        )
    return 0


def _cmd_import_mafile(args: argparse.Namespace) -> int:
    _import_mafile_path(args.path)
    return 0

def _cmd_export_backup(args: argparse.Namespace) -> int:
    selected_ids = _selected_backup_ids(args.steamid64)
    for warning in backup.unsafe_backup_path_warnings(args.path):
        print(_warning(f"Warning: {warning}"))
    print(_warning(f"This encrypted backup will contain Steam Guard secrets and session tokens for {len(selected_ids)} account(s)."))
    print(_muted("Store the backup and passphrase separately. steamguard-pc cannot recover a lost backup passphrase."))
    if args.include_revocation_code:
        print(_warning("Warning: this backup will include Steam Guard revocation codes."))
        print(_warning("Revocation codes can remove authenticators; include them only for private offline recovery backups."))
        revocation_expected = f"INCLUDE REVOCATION CODES {len(selected_ids)} ACCOUNTS"
        if input(_prompt(f"Type {revocation_expected!r} to include revocation codes: ")) != revocation_expected:
            print(_warning("Backup export cancelled."))
            return 1
    expected = f"EXPORT BACKUP {len(selected_ids)} ACCOUNTS"
    if input(_prompt(f"Type {expected!r} to write encrypted backup: ")) != expected:
        print(_warning("Backup export cancelled."))
        return 1

    passphrase = getpass.getpass(_prompt("Backup passphrase: "))
    repeated = getpass.getpass(_prompt("Repeat backup passphrase: "))
    if not passphrase or not repeated:
        raise ValueError("backup passphrase is required")
    if passphrase != repeated:
        raise ValueError("backup passphrases do not match")

    count = backup.export_accounts(
        args.path,
        passphrase,
        selected_ids,
        overwrite=args.force,
        include_revocation_code=args.include_revocation_code,
    )
    print(_success(f"Wrote encrypted backup for {count} account(s) to {args.path}."))
    return 0


def _cmd_import_backup(args: argparse.Namespace) -> int:
    for warning in backup.unsafe_backup_path_warnings(args.path):
        print(_warning(f"Warning: {warning}"))
    print(_warning("This will import Steam Guard secrets from an encrypted steamguard-pc backup."))
    if args.replace:
        print(_warning("Existing matching accounts will be overwritten with values from the backup."))
    else:
        print(_muted("Existing accounts are refused unless --replace is used."))
    if input(_prompt("Type 'IMPORT BACKUP' to import encrypted backup: ")) != "IMPORT BACKUP":
        print(_warning("Backup import cancelled."))
        return 1

    passphrase = getpass.getpass(_prompt("Backup passphrase: "))
    if not passphrase:
        raise ValueError("backup passphrase is required")
    count = backup.import_accounts(args.path, passphrase, replace=args.replace)
    print(_success(f"Imported encrypted backup for {count} account(s)."))
    return 0


def _cmd_set_cookies(args: argparse.Namespace) -> int:
    steam_login_secure, sessionid = _cookie_values_from_env()
    if steam_login_secure is None or sessionid is None:
        steam_login_secure = getpass.getpass(_prompt("steamLoginSecure: "))
        sessionid = getpass.getpass(_prompt("sessionid: "))

    session.save_community_cookies(args.steamid64, steam_login_secure, sessionid)
    print(_success(f"Stored Steam Community cookies for {args.steamid64}."))
    return 0


def _cmd_cookie_guide(args: argparse.Namespace) -> int:
    _print_cookie_guide()
    return 0


def _cmd_find_mafiles(args: argparse.Namespace) -> int:
    candidates = mafile.find_mafile_candidates(args.search_dir or None)
    if not candidates:
        print(_muted("No .maFile files found."))
        return 0

    for candidate in candidates:
        print(candidate)
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    print(_info("steamguard-pc setup"))
    print(_muted("Secrets are stored in Windows secret storage; config.json stores metadata only."))
    if args.mafile:
        imported, metadata = _import_mafile_path(args.mafile)
        _setup_cookies(
            metadata.steamid64,
            imported_had_cookies=bool(imported.steam_login_secure and imported.sessionid),
            skip_cookies=args.skip_cookies,
        )
    else:
        print(_info("Choose setup method:"))
        print(f"  {_value('1')}. Sign in and add a new mobile authenticator in this app")
        print(f"  {_value('2')}. Sign in only to store/refresh Steam Community cookies")
        print(f"  {_value('3')}. Import an existing .maFile (encrypted SDA files supported)")
        choice = input(_prompt("Setup method [1/2/3]: ")).strip()
        if choice == "1":
            metadata = _enroll_with_prompts()
        elif choice == "2":
            _, metadata = _login_and_store()
        elif choice == "3":
            mafile_path = _select_mafile_path(None)
            imported, metadata = _import_mafile_path(mafile_path)
            _setup_cookies(
                metadata.steamid64,
                imported_had_cookies=bool(imported.steam_login_secure and imported.sessionid),
                skip_cookies=args.skip_cookies,
            )
        else:
            raise ValueError("setup cancelled")

    print(_success("Setup complete."))
    print(_info(f"Next: steamguard-pc code {metadata.steamid64}"))
    print(_info(f"Confirmations: steamguard-pc confirmations {metadata.steamid64}"))
    return 0


def _cmd_code(args: argparse.Namespace) -> int:
    if args.timestamp is not None and args.steam_time:
        raise ValueError("--timestamp and --steam-time cannot be combined")
    timestamp = steam_time.query_steam_time() if args.steam_time else args.timestamp
    if timestamp is None:
        timestamp = int(time.time())
    shared_secret = storage.get_required_secret(args.steamid64, "shared_secret")
    code = steam_totp(shared_secret, timestamp)
    if args.plain:
        print(code)
    else:
        remaining = seconds_remaining(timestamp)
        print(f"{_value(code)} expires_in={remaining}s")
        print(_muted("Clock must be synchronized with Steam; sync Windows time if Steam rejects this code."))
    return 0


def _cmd_confirmations(args: argparse.Namespace) -> int:
    _, _, _, current = _load_current_confirmations(args.steamid64)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": confirmation.id,
                        "creator_id": confirmation.creator_id,
                        "type": confirmation.type,
                        "type_name": confirmation.type_name,
                        "headline": confirmation.headline,
                        "summary": confirmation.summary,
                        "creation_time": confirmation.creation_time,
                    }
                    for confirmation in current
                ],
                indent=2,
            )
        )
        return 0

    if not current:
        print(_muted("No pending confirmations."))
        return 0

    for confirmation in current:
        _print_confirmation_row(confirmation)
    return 0


def _cmd_revocation_code(args: argparse.Namespace) -> int:
    metadata = storage.load_accounts().get(args.steamid64)
    if metadata is None:
        raise KeyError(f"missing account metadata for {args.steamid64}")
    print(_warning("The Steam Guard revocation code can remove this authenticator from the account."))
    print(_muted("It is R followed by five digits, not the seven-digit recovery code Steam requests during sign-in recovery."))
    print(_warning("Only reveal it in a private terminal where nobody else can see or record it."))
    expected = f"SHOW REVOCATION CODE {args.steamid64}"
    if input(_prompt(f"Type {expected!r} to show the revocation code: ")) != expected:
        print(_warning("Revocation code display cancelled."))
        return 1

    revocation_code = storage.get_required_secret(args.steamid64, "revocation_code")
    _print_revocation_code(metadata, revocation_code)
    return 0

def _cmd_recovery_codes(args: argparse.Namespace) -> int:
    metadata = storage.load_accounts().get(args.steamid64)
    if metadata is None:
        raise KeyError(f"missing account metadata for {args.steamid64}")
    label = _account_label(metadata)
    print(_info("Steam recovery codes are one-time login codes for official Steam recovery prompts."))
    print(_warning("Creating a new set may replace older emergency codes. Store the new set offline immediately."))
    expected = f"CREATE RECOVERY CODES {args.steamid64}"
    if input(_prompt(f"Type {expected!r} to create recovery codes: ")) != expected:
        print(_warning("Recovery-code creation cancelled."))
        return 1

    access_token, _ = session.refresh_auth_tokens(args.steamid64)
    client = enrollment.EnrollmentClient()
    codes = client.create_emergency_codes(access_token)
    if codes is None:
        confirmation_code = input(_prompt("Steam recovery-code confirmation code from email or SMS: ")).strip()
        if not confirmation_code:
            raise ValueError("Steam recovery-code confirmation code is required")
        codes = client.create_emergency_codes(access_token, confirmation_code)
    if codes is None:
        raise EnrollmentError("Steam recovery-code response is missing codes")

    print(_warning(f"Steam recovery codes for {label}:"))
    for code in codes:
        print(code)
    print(_warning("Store these one-time codes offline. They are not saved by steamguard-pc."))
    return 0

def _cmd_remove_authenticator(args: argparse.Namespace) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        metadata = storage.load_accounts().get(args.steamid64)
        if metadata is None:
            raise KeyError(f"missing account metadata for {args.steamid64}")
        label = _account_label(metadata)

        print(_danger(f"Remove Steam Guard mobile authenticator from {label}?"))
        print(_warning("This changes Steam account security state. Steam says removal reduces account security and blocks trading or Community Market selling for 15 days."))
        print(_muted("steamguard-pc will delete local authenticator secrets after Steam confirms removal. Local account metadata and sign-in/session tokens are kept."))
        expected = f"REMOVE AUTHENTICATOR {args.steamid64}"
        if input(_prompt(f"Type {expected!r} to remove this authenticator: ")) != expected:
            print(_warning("Authenticator removal cancelled."))
            return 1

        revocation_code = storage.get_required_secret(args.steamid64, "revocation_code")
        access_token, _ = session.refresh_auth_tokens(args.steamid64)
        enrollment.EnrollmentClient().remove_authenticator(access_token, revocation_code)
        storage.delete_authenticator_secrets(args.steamid64)

        print(_success(f"Removed Steam Guard mobile authenticator from {label}."))
        print(_muted(f"Deleted local authenticator secrets. Sign-in/session tokens remain; run `steamguard-pc accounts --delete {args.steamid64}` to delete the local account."))
        return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        metadata, identity_secret, community_session, target = _find_current_confirmation(
            args.steamid64,
            args.confirmation_id,
        )
        _print_confirmation_detail(target, _account_label(metadata))
        _print_trade_offer_id(
            community_session,
            args.steamid64,
            metadata.device_id or "",
            identity_secret,
            args.confirmation_id,
        )
        expected = f"APPROVE {args.confirmation_id}"
        if input(_prompt(f"Type {expected!r} to approve: ")) != expected:
            print(_warning("Approval cancelled."))
            return 1

        try:
            confirmations.respond_to_confirmation_id(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                args.confirmation_id,
                accept=True,
            )
        except confirmations.NeedAuthenticationError:
            community_session = session.refresh_community_session(args.steamid64)
            confirmations.respond_to_confirmation_id(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                args.confirmation_id,
                accept=True,
            )
        print(_success(f"Approved {args.confirmation_id}."))
        return 0


def _cmd_cancel(args: argparse.Namespace) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        metadata, identity_secret, community_session, target = _find_current_confirmation(
            args.steamid64,
            args.confirmation_id,
        )
        _print_confirmation_detail(target, _account_label(metadata))
        _print_trade_offer_id(
            community_session,
            args.steamid64,
            metadata.device_id or "",
            identity_secret,
            args.confirmation_id,
        )
        expected = f"CANCEL {args.confirmation_id}"
        if input(_prompt(f"Type {expected!r} to cancel: ")) != expected:
            print(_warning("Cancellation cancelled."))
            return 1

        try:
            confirmations.respond_to_confirmation_id(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                args.confirmation_id,
                accept=False,
            )
        except confirmations.NeedAuthenticationError:
            community_session = session.refresh_community_session(args.steamid64)
            confirmations.respond_to_confirmation_id(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                args.confirmation_id,
                accept=False,
            )
        print(_success(f"Cancelled {args.confirmation_id}."))
        return 0

def _cmd_batch_confirm(args: argparse.Namespace, accept: bool) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        metadata, identity_secret, community_session, current = _load_current_confirmations(args.steamid64)
        if not current:
            print(_muted("No pending confirmations."))
            return 0

        _print_batch_confirmation_review(metadata, community_session, identity_secret, current)
        if accept:
            unsafe = _unsafe_batch_approval_confirmations(current)
            if unsafe:
                print(_danger("Batch approval blocked: approve-all only supports Trade and Market listing confirmations."))
                for confirmation in unsafe:
                    print(_warning(f"blocked: {confirmation.id}\t{_confirmation_type(confirmation)}\t{confirmation.creator_id or '-'}"))
                return 1

        action = "APPROVE" if accept else "CANCEL"
        noun = "approval" if accept else "cancellation"
        expected = f"{action} ALL {len(current)} CONFIRMATIONS {args.steamid64}"
        if input(_prompt(f"Type {expected!r} to {'approve' if accept else 'cancel'} all listed confirmations: ")) != expected:
            print(_warning(f"Batch {noun} cancelled."))
            return 1

        confirmation_ids = [item.id for item in current]
        try:
            acted = confirmations.respond_to_confirmation_ids(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                confirmation_ids,
                accept=accept,
            )
        except confirmations.NeedAuthenticationError:
            community_session = session.refresh_community_session(args.steamid64)
            acted = confirmations.respond_to_confirmation_ids(
                community_session,
                args.steamid64,
                metadata.device_id or "",
                identity_secret,
                confirmation_ids,
                accept=accept,
            )

        verb = "Approved" if accept else "Cancelled"
        print(_success(f"{verb} {len(acted)} confirmations."))
        return 0


def _cmd_approve_all(args: argparse.Namespace) -> int:
    return _cmd_batch_confirm(args, accept=True)


def _cmd_cancel_all(args: argparse.Namespace) -> int:
    return _cmd_batch_confirm(args, accept=False)


def _parser_command_names(parser: argparse.ArgumentParser) -> list[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(str(command) for command in action.choices)
    return []


def _parser_command_parsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _parser_global_options(parser: argparse.ArgumentParser) -> list[str]:
    global_options: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        global_options.update(action.option_strings)
    return sorted(global_options)


def _parser_command_options(parser: argparse.ArgumentParser) -> dict[str, list[str]]:
    options: dict[str, list[str]] = {}
    for command, command_parser in _parser_command_parsers(parser).items():
        command_options: set[str] = set()
        for action in command_parser._actions:
            command_options.update(action.option_strings)
        options[command] = sorted(command_options)
    return options


def _shell_words(words: list[str]) -> str:
    return " ".join(words)


def _powershell_words(words: list[str]) -> str:
    return ", ".join(f"'{word}'" for word in words)


def _completion_script(
    shell: str,
    commands: list[str],
    global_options: list[str],
    command_options: dict[str, list[str]],
) -> str:
    top_level_words = _shell_words([*global_options, *commands])
    color_words = _shell_words(sorted(COLOR_MODES))
    if shell == "bash":
        option_cases = "\n".join(
            f'    {command}) COMPREPLY=( $(compgen -W "{_shell_words(options)}" -- "$cur") ) ;;'
            for command, options in command_options.items()
        )
        return f"""_steamguard_pc_complete() {{
  local cur="${{COMP_WORDS[COMP_CWORD]}}"
  if [[ ${{COMP_CWORD}} -gt 1 && "${{COMP_WORDS[COMP_CWORD-1]}}" == "--color" ]]; then
    COMPREPLY=( $(compgen -W "{color_words}" -- "$cur") )
    return
  fi
  if [[ ${{COMP_CWORD}} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "{top_level_words}" -- "$cur") )
    return
  fi

  case "${{COMP_WORDS[1]}}" in
{option_cases}
    *) COMPREPLY=() ;;
  esac
}}
complete -F _steamguard_pc_complete steamguard-pc
"""
    if shell == "zsh":
        zsh_top_level = _shell_words([*global_options, *commands])
        option_cases = "\n".join(
            f"    {command}) options=({_shell_words(options)}); _describe 'option' options ;;"
            for command, options in command_options.items()
        )
        return f"""#compdef steamguard-pc
_steamguard_pc() {{
  local -a top_level options color_modes
  top_level=({zsh_top_level})
  color_modes=({color_words})
  if [[ $words[$((CURRENT - 1))] == "--color" ]]; then
    _describe 'color mode' color_modes
    return
  fi
  if (( CURRENT == 2 )); then
    _describe 'command' top_level
    return
  fi

  case "$words[2]" in
{option_cases}
    *) return 1 ;;
  esac
}}
compdef _steamguard_pc steamguard-pc
"""

    powershell_top_level = _powershell_words([*global_options, *commands])
    powershell_color_modes = _powershell_words(sorted(COLOR_MODES))
    option_cases = "\n".join(
        f"    '{command}' {{ $candidates = @({_powershell_words(options)}); break }}"
        for command, options in command_options.items()
    )
    return f"""Register-ArgumentCompleter -Native -CommandName steamguard-pc -ScriptBlock {{
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = @({powershell_top_level})
  $candidates = $commands
  if ($commandAst.CommandElements.Count -gt 1 -and $commandAst.CommandElements[$commandAst.CommandElements.Count - 2].Value -eq '--color') {{
    $candidates = @({powershell_color_modes})
  }} elseif ($commandAst.CommandElements.Count -gt 2) {{
    switch ($commandAst.CommandElements[1].Value) {{
{option_cases}
      default {{ $candidates = @() }}
    }}
  }}
  $candidates |
    Where-Object {{ $_ -like "$wordToComplete*" }} |
    ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}
}}
"""


def _cmd_completion(args: argparse.Namespace) -> int:
    parser = _build_parser()
    print(_completion_script(args.shell, _parser_command_names(parser), _parser_global_options(parser), _parser_command_options(parser)), end="")
    return 0


def _cmd_help(args: argparse.Namespace) -> int:
    parser = _build_parser()
    if args.command is None:
        parser.print_help()
        return 0

    command_parsers = _parser_command_parsers(parser)
    command_parser = command_parsers.get(args.command)
    if command_parser is None:
        matches = difflib.get_close_matches(args.command, command_parsers, n=1, cutoff=0.55)
        suggestion = f" Did you mean '{matches[0]}'?" if matches else ""
        raise ValueError(f"unknown command {args.command!r}.{suggestion}")

    command_parser.print_help()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="steamguard-pc",
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=_HelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    parser.add_argument(
        "--color",
        choices=sorted(COLOR_MODES),
        default="auto",
        help="Control colored output: auto, always, or never (default: auto).",
    )
    parser.add_argument("--no-color", action="store_const", dest="color", const="never", help="Disable colored output.")
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
        description="Use `steamguard-pc COMMAND -h` for command-specific options.",
        required=True,
    )

    completion = subparsers.add_parser(
        "completion",
        help="Print shell completion setup.",
        description="Print a deterministic shell completion script for steamguard-pc commands.",
        formatter_class=_HelpFormatter,
    )
    completion.add_argument("shell", choices=("bash", "zsh", "powershell"), help="Shell to generate completion for.")
    completion.set_defaults(func=_cmd_completion)

    help_command = subparsers.add_parser(
        "help",
        help="Show help for steamguard-pc or one command.",
        description="Show top-level help or command-specific help without remembering -h placement.",
        formatter_class=_HelpFormatter,
    )
    help_command.add_argument("command", nargs="?", metavar="COMMAND", help="Command to show help for.")
    help_command.set_defaults(func=_cmd_help)

    setup = subparsers.add_parser(
        "setup",
        help="Guided first-run setup.",
        description=(
            "Guided setup: enroll a new authenticator, sign in for Steam Community cookies,\n"
            "or import a Steam Desktop Authenticator .maFile. Imported SDA session\n"
            "tokens/cookies are used when present."
        ),
        formatter_class=_HelpFormatter,
    )
    setup.add_argument(
        "--mafile",
        metavar="PATH",
        help="Import this .maFile; use session tokens/cookies when present and prompt for encrypted SDA passkey.",
    )
    setup.add_argument(
        "--skip-cookies",
        action="store_true",
        help="Do not store Steam Community cookies after .maFile import.",
    )
    setup.set_defaults(func=_cmd_setup)

    enroll = subparsers.add_parser(
        "enroll",
        help="Sign in and add a mobile authenticator.",
        description=(
            "Sign in with Steam credentials, add a new mobile authenticator,\n"
            "store its secrets, and finalize it with Steam's activation code."
        ),
        formatter_class=_HelpFormatter,
    )
    enroll.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam login name; prompts if omitted.")
    enroll.set_defaults(func=_cmd_enroll)

    login = subparsers.add_parser(
        "login",
        help="Sign in and store a Community session.",
        description=(
            "Sign in with Steam credentials and store the refresh/access tokens\n"
            "and Steam Community cookies used by confirmation commands."
        ),
        formatter_class=_HelpFormatter,
    )
    login.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam login name; prompts if omitted.")
    login.set_defaults(func=_cmd_login)

    login_confirmations = subparsers.add_parser(
        "login-confirmations",
        help="List pending Steam login confirmations.",
        description="Fetch pending Steam login approval requests for a stored account and show IP, location, platform, and device details.",
        formatter_class=_HelpFormatter,
    )
    login_confirmations.add_argument("steamid64", metavar="STEAMID64", help="Stored account to query.")
    login_confirmations.set_defaults(func=_cmd_login_confirmations)

    approve_login = subparsers.add_parser(
        "approve-login",
        help="Approve one Steam login confirmation.",
        description="Show a pending Steam login request, then approve it after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    approve_login.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    approve_login.add_argument("client_id", metavar="CLIENT_ID", help="Client ID printed by the login-confirmations command.")
    approve_login.set_defaults(func=_cmd_approve_login)

    deny_login = subparsers.add_parser(
        "deny-login",
        help="Deny one Steam login confirmation.",
        description="Show a pending Steam login request, then deny it after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    deny_login.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    deny_login.add_argument("client_id", metavar="CLIENT_ID", help="Client ID printed by the login-confirmations command.")
    deny_login.set_defaults(func=_cmd_deny_login)

    import_mafile = subparsers.add_parser(
        "import-mafile",
        help="Import a Steam Desktop Authenticator file.",
        description=(
            "Import shared/identity secrets and SDA session fields from a .maFile.\n"
            "Encrypted Steam Desktop Authenticator files prompt for the SDA passkey."
        ),
        formatter_class=_HelpFormatter,
    )
    import_mafile.add_argument("path", metavar="PATH", help="Path to the .maFile to import.")
    import_mafile.set_defaults(func=_cmd_import_mafile)

    export_backup = subparsers.add_parser(
        "export-backup",
        help="Export an encrypted backup.",
        description=(
            "Export selected accounts, authenticator secrets, and session tokens\n"
            "to an encrypted steamguard-pc backup after exact typed consent."
        ),
        formatter_class=_HelpFormatter,
    )
    export_backup.add_argument("path", metavar="PATH", help="Destination backup file path.")
    export_backup.add_argument("steamid64", nargs="*", metavar="STEAMID64", help="Accounts to export; defaults to every stored account.")
    export_backup.add_argument("--force", action="store_true", help="Overwrite an existing backup file.")
    export_backup.add_argument(
        "--include-revocation-code",
        action="store_true",
        help="Include stored R##### revocation codes after an extra exact typed warning.",
    )
    export_backup.set_defaults(func=_cmd_export_backup)

    import_backup = subparsers.add_parser(
        "import-backup",
        help="Import an encrypted backup.",
        description="Import accounts from an encrypted steamguard-pc backup after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    import_backup.add_argument("path", metavar="PATH", help="Encrypted steamguard-pc backup file path.")
    import_backup.add_argument("--replace", action="store_true", help="Overwrite matching accounts already stored locally.")
    import_backup.set_defaults(func=_cmd_import_backup)

    code = subparsers.add_parser(
        "code",
        help="Print a Steam Guard login code.",
        description="Print the current 5-character Steam Guard login code and seconds remaining.",
        formatter_class=_HelpFormatter,
    )
    code.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    code.add_argument("--timestamp", type=int, metavar="UNIX_TIME", help="Generate the code for this Unix timestamp.")
    code.add_argument("--steam-time", action="store_true", help="Query Steam server time before generating the code.")
    code.add_argument("--plain", action="store_true", help="Print only the 5-character code for copying or scripts.")
    code.set_defaults(func=_cmd_code)

    pending = subparsers.add_parser(
        "confirmations",
        help="List pending mobile confirmations.",
        description="Fetch and print pending Steam mobile confirmations for a stored account.",
        formatter_class=_HelpFormatter,
    )
    pending.add_argument("steamid64", metavar="STEAMID64", help="Stored account to query.")
    pending.add_argument("--json", action="store_true", help="Print pending confirmations as JSON.")
    pending.set_defaults(func=_cmd_confirmations)

    approve = subparsers.add_parser(
        "approve",
        help="Approve one pending confirmation.",
        description=(
            "Fetch the current confirmation, show its details, then approve it after "
            "the exact typed phrase."
        ),
        formatter_class=_HelpFormatter,
    )
    approve.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    approve.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="ID printed by the confirmations command.")
    approve.set_defaults(func=_cmd_approve)

    cancel = subparsers.add_parser(
        "cancel",
        help="Cancel one pending confirmation.",
        description=(
            "Fetch the current confirmation, show its details, then cancel it after "
            "the exact typed phrase."
        ),
        formatter_class=_HelpFormatter,
    )
    cancel.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    cancel.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="ID printed by the confirmations command.")
    cancel.set_defaults(func=_cmd_cancel)

    approve_all = subparsers.add_parser(
        "approve-all",
        help="Approve all trade or market confirmations.",
        description=(
            "Review pending confirmations; approve only when every displayed item\n"
            "is a Trade or Market listing confirmation."
        ),
        formatter_class=_HelpFormatter,
    )
    approve_all.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    approve_all.set_defaults(func=_cmd_approve_all)

    cancel_all = subparsers.add_parser(
        "cancel-all",
        help="Cancel all pending confirmations.",
        description="Review every pending confirmation, then cancel the displayed batch after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    cancel_all.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    cancel_all.set_defaults(func=_cmd_cancel_all)

    revocation_code = subparsers.add_parser(
        "revocation-code",
        help="Reveal the stored authenticator revocation code.",
        description="Reveal the stored R##### revocation code after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    revocation_code.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    revocation_code.set_defaults(func=_cmd_revocation_code)

    remove_authenticator = subparsers.add_parser(
        "remove-authenticator",
        usage="steamguard-pc remove-authenticator STEAMID64",
        help="Remove the mobile authenticator from Steam.",
        description="Remove the Steam Guard mobile authenticator from Steam after exact typed consent, then delete local authenticator secrets.",
        formatter_class=_HelpFormatter,
    )
    remove_authenticator.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    remove_authenticator.set_defaults(func=_cmd_remove_authenticator)

    recovery_codes = subparsers.add_parser(
        "recovery-codes",
        help="Create one-time Steam recovery codes.",
        description=(
            "Create one-time Steam recovery codes after exact typed consent;\n"
            "Steam may require an email or SMS confirmation code."
        ),
        formatter_class=_HelpFormatter,
    )
    recovery_codes.add_argument("steamid64", metavar="STEAMID64", help="Stored account to use.")
    recovery_codes.set_defaults(func=_cmd_recovery_codes)

    accounts = subparsers.add_parser(
        "accounts",
        help="List or delete local accounts.",
        description=(
            "List stored account metadata, or delete one local account and all of\n"
            "its stored secrets after exact typed consent."
        ),
        formatter_class=_HelpFormatter,
    )
    accounts.add_argument("--delete", metavar="STEAMID64", help="Delete this local account and all stored secrets; Steam is not changed.")
    accounts.add_argument("--json", action="store_true", help="Print account metadata as JSON without secrets.")
    accounts.set_defaults(func=_cmd_accounts)

    find_mafiles = subparsers.add_parser(
        "find-mafiles",
        help="Find Steam Desktop Authenticator .maFile files.",
        description="Search default locations or supplied directories and print .maFile candidates.",
        formatter_class=_HelpFormatter,
    )
    find_mafiles.add_argument("search_dir", nargs="*", metavar="DIR", help="Directories to search; defaults to common SDA locations.")
    find_mafiles.set_defaults(func=_cmd_find_mafiles)

    cookie_guide = subparsers.add_parser(
        "cookie-guide",
        help="Show browser cookie-copy steps.",
        description="Show how to copy steamLoginSecure and sessionid from steamcommunity.com.",
        formatter_class=_HelpFormatter,
    )
    cookie_guide.set_defaults(func=_cmd_cookie_guide)

    set_cookies = subparsers.add_parser(
        "set-cookies",
        help="Store Steam Community cookies manually.",
        description=(
            "Store steamLoginSecure and sessionid for a stored account from\n"
            "environment variables or hidden prompts."
        ),
        formatter_class=_HelpFormatter,
    )
    set_cookies.add_argument("steamid64", metavar="STEAMID64", help="Stored account to update.")
    set_cookies.set_defaults(func=_cmd_set_cookies)

    return parser


def main(argv: list[str] | None = None) -> int:
    global _COLOR_MODE
    previous_color_mode = _COLOR_MODE
    _COLOR_MODE = _argv_color_mode(argv)
    try:
        parser = _build_parser()
        try:
            args = parser.parse_args(argv)
            _COLOR_MODE = args.color
            return int(args.func(args))
        except KeyboardInterrupt:
            print(_color("\nInterrupted; no changes made.", COLOR_INTERRUPT, sys.stderr), file=sys.stderr)
            return 130
        except EXPECTED_ERRORS as exc:
            print(_color(_exception_text(exc), COLOR_ERROR, sys.stderr), file=sys.stderr)
            return 1
    finally:
        _COLOR_MODE = previous_color_mode


if __name__ == "__main__":
    raise SystemExit(main())
