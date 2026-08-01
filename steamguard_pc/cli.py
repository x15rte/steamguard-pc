import argparse
import getpass
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

from . import auth, backup, confirmations, enrollment, mafile, operation_lock, session, steam_time, storage
from .auth import GuardAction, LoginResult, SteamAuthError
from .confirmations import Confirmation, ConfirmationError
from .crypto import generate_device_id, seconds_remaining, steam_totp
from .enrollment import EnrollmentError
from .session import SessionExpiredError
from .storage import SecretStorageUnavailable


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


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=36, width=100, **kwargs)


HELP_DESCRIPTION = """\
SteamGuardPC is a Windows-focused Steam Guard helper.

Stores secrets in keyring and handles login codes, sessions, authenticator
enrollment, revocation-code display, and one-at-a-time confirmations.
"""


HELP_EPILOG = """\
Common workflows:
  steamguard-pc setup
      Guided first run.

  steamguard-pc accounts --delete STEAMID64
      Delete one local account and its stored secrets after typed consent.

  steamguard-pc code STEAMID64
      Print a 5-character login code and seconds remaining.

  steamguard-pc confirmations STEAMID64
      List pending mobile confirmations.

  steamguard-pc approve STEAMID64 CONFIRMATION_ID
  steamguard-pc cancel  STEAMID64 CONFIRMATION_ID
      Review one confirmation, type APPROVE/CANCEL <id>, then submit.

  steamguard-pc approve-all STEAMID64
  steamguard-pc cancel-all  STEAMID64
      Review every pending confirmation, type APPROVE/CANCEL ALL <count> CONFIRMATIONS <SteamID64>, then submit.

  steamguard-pc revocation-code STEAMID64
      Reveal the stored R##### code after typed consent.

  steamguard-pc recovery-codes STEAMID64
      Create one-time recovery codes after typed consent.

  steamguard-pc export-backup PATH [STEAMID64 ...] [--include-revocation-code]
      Write an encrypted SteamGuardPC backup after typed consent.

  steamguard-pc import-backup PATH
      Import an encrypted SteamGuardPC backup after typed consent.

Run `steamguard-pc COMMAND -h` for command-specific options.
"""


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
                confirmation.id,
                _confirmation_type(confirmation),
                confirmation.creator_id or "-",
                confirmation.headline or "-",
                _summary_text(confirmation.summary),
            ]
        )
    )


def _print_confirmation_detail(confirmation: Confirmation, account_label: str | None = None) -> None:
    if account_label is not None:
        print(f"account: {account_label}")
    print(f"id: {confirmation.id}")
    print(f"type: {_confirmation_type(confirmation)}")
    print(f"creator_id: {confirmation.creator_id or '-'}")
    print(f"headline: {confirmation.headline or '-'}")
    print(f"summary: {_summary_text(confirmation.summary)}")


def _print_trade_offer_id(
    community_session: object,
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
    print(f"trade_offer_id: {trade_offer_id or 'unavailable'}")

def _print_batch_confirmation_review(
    metadata: storage.AccountMetadata,
    community_session: object,
    identity_secret: str,
    confirmations_to_review: list[Confirmation],
) -> None:
    account_label = _account_label(metadata)
    count = len(confirmations_to_review)
    print(f"Pending confirmations for {account_label}: {count}")
    for index, confirmation in enumerate(confirmations_to_review, start=1):
        print(f"--- confirmation {index} of {count} ---")
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


def _confirmation_context(steamid64: str) -> tuple[storage.AccountMetadata, str, object]:
    metadata = _account_metadata(steamid64)
    identity_secret = storage.get_required_secret(steamid64, "identity_secret")
    community_session = session.get_community_session(steamid64)
    return metadata, identity_secret, community_session


def _load_current_confirmations(
    steamid64: str,
) -> tuple[storage.AccountMetadata, str, object, list[Confirmation]]:
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


def _find_current_confirmation(steamid64: str, confirmation_id: str) -> tuple[storage.AccountMetadata, str, object, Confirmation]:
    metadata, identity_secret, community_session, current = _load_current_confirmations(steamid64)
    target = next((item for item in current if item.id == confirmation_id), None)
    if target is None:
        raise confirmations.ConfirmationNotFoundError(f"confirmation {confirmation_id} not found")
    return metadata, identity_secret, community_session, target



def _cookie_values_from_env() -> tuple[str | None, str | None]:
    return (
        os.environ.get("STEAMGUARDPC_STEAM_LOGIN_SECURE"),
        os.environ.get("STEAMGUARDPC_SESSIONID"),
    )


def _print_cookie_guide() -> None:
    print(COOKIE_GUIDE.strip())


def _import_mafile_path(path: str | Path) -> tuple[mafile.ImportedSteamGuard, storage.AccountMetadata]:
    for warning in mafile.unsafe_import_path_warnings(path):
        print(f"Warning: {warning}", file=sys.stderr)

    try:
        imported = mafile.load_mafile(path)
    except mafile.EncryptedMaFileRequiresPasskey:
        passkey = getpass.getpass("SDA encryption passkey: ")
        if not passkey:
            raise ValueError("SDA encryption passkey is required")
        try:
            imported = mafile.load_mafile(path, passkey=passkey)
        finally:
            passkey = ""
    metadata = storage.store_imported_guard(imported)
    label = metadata.account_name or metadata.steamid64
    print(f"Imported {label} ({metadata.steamid64})")
    if imported.revocation_code:
        print(f"Steam Guard revocation code was stored. Run `steamguard-pc revocation-code {metadata.steamid64}` in a private terminal and store it offline.")
    return imported, metadata


def _select_mafile_path(explicit_path: str | None) -> Path:
    if explicit_path:
        return Path(explicit_path)

    candidates = mafile.find_mafile_candidates()
    if candidates:
        print("Found .maFile candidates:")
        for index, candidate in enumerate(candidates, start=1):
            print(f"  {index}. {candidate}")
        print("Choose a number, type another path, or press Enter to cancel.")
        choice = input("maFile: ").strip()
        if not choice:
            raise ValueError("setup cancelled before import")
        if choice.isdecimal():
            selected = int(choice)
            if 1 <= selected <= len(candidates):
                return candidates[selected - 1]
        return Path(choice)

    print("No .maFile files found in common locations.")
    choice = input("Path to .maFile (blank to cancel): ").strip()
    if not choice:
        raise ValueError("setup cancelled before import")
    return Path(choice)


def _store_cookies_from_env(steamid64: str) -> bool:
    steam_login_secure, sessionid = _cookie_values_from_env()
    if bool(steam_login_secure) != bool(sessionid):
        raise ValueError(
            "set both STEAMGUARDPC_STEAM_LOGIN_SECURE and STEAMGUARDPC_SESSIONID, or set neither"
        )
    if not steam_login_secure or not sessionid:
        return False

    session.save_community_cookies(steamid64, steam_login_secure, sessionid)
    print(f"Stored Steam Community cookies for {steamid64} from environment variables.")
    return True


def _setup_cookies(steamid64: str, imported_had_cookies: bool, skip_cookies: bool) -> None:
    if skip_cookies:
        print("Skipped cookie setup. Run `steamguard-pc cookie-guide` then `steamguard-pc set-cookies` when needed.")
        return

    if _store_cookies_from_env(steamid64):
        return

    if imported_had_cookies:
        print("Steam Community cookies were imported from the .maFile.")
        print(f"If confirmations fail, refresh them with `steamguard-pc set-cookies {steamid64}`.")
        return

    _print_cookie_guide()
    if input("Store Steam Community cookies now? [y/N]: ").strip().casefold() != "y":
        print(f"Skipped cookie setup. Run `steamguard-pc set-cookies {steamid64}` before confirmations.")
        return

    steam_login_secure = getpass.getpass("steamLoginSecure: ")
    sessionid = getpass.getpass("sessionid: ")
    session.save_community_cookies(steamid64, steam_login_secure, sessionid)
    print(f"Stored Steam Community cookies for {steamid64}.")


def _code_for_login(action: GuardAction, auth_session: auth.AuthSession) -> str | None:
    if action.type == auth.GUARD_DEVICE_CODE and auth_session.steamid64:
        shared_secret = storage.get_secret(auth_session.steamid64, "shared_secret")
        if shared_secret:
            print(f"Using stored Steam Guard code for {auth_session.steamid64}.")
            return steam_totp(shared_secret)

    detail = f" ({action.message})" if action.message else ""
    return input(f"Steam Guard {action.label}{detail}: ").strip()


def _wait_for_login_confirmation(actions: list[GuardAction]) -> None:
    labels = ", ".join(action.label for action in actions)
    print(f"Approve the Steam login prompt using: {labels}.")
    input("Press Enter after approving it.")


def _login_with_prompts(account_name: str | None = None) -> LoginResult:
    account_name = account_name or input("Steam account name: ").strip()
    if not account_name:
        raise ValueError("Steam account name is required")
    password = getpass.getpass("Steam password: ")
    print("Signing in with Steam. Password is sent only to Steam over HTTPS.")
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
    print(f"Signed in and stored Steam Community session for {metadata.account_name or metadata.steamid64} ({metadata.steamid64}).")
    return result, metadata


def _print_revocation_code(metadata: storage.AccountMetadata, revocation_code: str) -> None:
    label = metadata.account_name or metadata.steamid64
    print(f"Steam Guard revocation code for {label} ({metadata.steamid64}): {revocation_code}")
    print("Store this code offline. Steam formats it as R followed by five digits, and it can remove this authenticator from the account.")
    print("This is not the seven-digit recovery code Steam requests during account sign-in recovery.")


def _enroll_with_prompts(account_name: str | None = None) -> storage.AccountMetadata:
    result, metadata = _login_and_store(account_name)
    print("Adding a new mobile authenticator changes account security state and can affect trade/market holds.")
    phrase = f"ADD AUTHENTICATOR {result.steamid64}"
    if input(f"Type {phrase!r} to continue: ") != phrase:
        raise ValueError("authenticator enrollment cancelled")

    has_linked_phone = input("Have you linked a verified SMS-capable phone number to this Steam account? [y/N]: ").strip().casefold() == "y"
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
    print("Authenticator secrets were stored before finalization.")
    if imported.revocation_code:
        _print_revocation_code(metadata, imported.revocation_code)
    if has_linked_phone:
        print("Steam should send the activation code by SMS to the linked phone number.")
    else:
        print("Steam may send the activation code by email when it offers the no-phone path.")
    resend_phrase = f"SEND ACTIVATION EMAIL {result.steamid64}"
    print(f"If no code arrives, type {resend_phrase!r} instead of the code to ask Steam to email another activation code.")
    activation_code = input("Steam activation code from email or SMS: ").strip()
    validate_sms_code = has_linked_phone
    if activation_code == resend_phrase:
        client.send_activation_email(result.access_token, result.steamid64)
        print("Requested an activation-code email from Steam.")
        validate_sms_code = False
        activation_code = input("Steam activation code from email or SMS: ").strip()
    if not activation_code:
        raise ValueError("Steam activation code is required")
    client.finalize_authenticator(
        result.access_token,
        result.steamid64,
        imported.shared_secret,
        activation_code,
        validate_sms_code=validate_sms_code,
    )
    print(f"Authenticator added and finalized for {metadata.account_name or metadata.steamid64} ({metadata.steamid64}).")
    if imported.revocation_code:
        print(f"Stored revocation code remains available with `steamguard-pc revocation-code {metadata.steamid64}`.")
    return metadata


def _cmd_login(args: argparse.Namespace) -> int:
    _login_and_store(args.account_name)
    return 0


def _cmd_enroll(args: argparse.Namespace) -> int:
    _enroll_with_prompts(args.account_name)
    return 0

def _delete_account_with_consent(steamid64: str) -> int:
    with operation_lock.account_operation_lock(steamid64):
        metadata = storage.load_accounts().get(steamid64)
        if metadata is None:
            raise KeyError(f"missing account metadata for {steamid64}")

        label = _account_label(metadata)
        print(f"Delete stored account {label}?")
        print("This removes local SteamGuardPC metadata and all stored secrets for this account.")
        print("This does not remove the authenticator from Steam.")
        expected = f"DELETE ACCOUNT {steamid64}"
        if input(f"Type {expected!r} to delete this account: ") != expected:
            print("Account deletion cancelled.")
            return 1

        deleted = storage.delete_account(steamid64)
        print(f"Deleted account {_account_label(deleted)}.")
        return 0


def _cmd_accounts(args: argparse.Namespace) -> int:
    if args.delete:
        return _delete_account_with_consent(args.delete)

    accounts = storage.load_accounts()
    if not accounts:
        print("No accounts imported.")
        return 0

    for metadata in sorted(accounts.values(), key=lambda account: account.steamid64):
        print(
            "\t".join(
                [
                    metadata.steamid64,
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
        print(f"Warning: {warning}")
    print(f"This encrypted backup will contain Steam Guard secrets and session tokens for {len(selected_ids)} account(s).")
    print("Store the backup and passphrase separately. SteamGuardPC cannot recover a lost backup passphrase.")
    if args.include_revocation_code:
        print("Warning: this backup will include Steam Guard revocation codes.")
        print("Revocation codes can remove authenticators; include them only for private offline recovery backups.")
        revocation_expected = f"INCLUDE REVOCATION CODES {len(selected_ids)} ACCOUNTS"
        if input(f"Type {revocation_expected!r} to include revocation codes: ") != revocation_expected:
            print("Backup export cancelled.")
            return 1
    expected = f"EXPORT BACKUP {len(selected_ids)} ACCOUNTS"
    if input(f"Type {expected!r} to write encrypted backup: ") != expected:
        print("Backup export cancelled.")
        return 1

    passphrase = getpass.getpass("Backup passphrase: ")
    repeated = getpass.getpass("Repeat backup passphrase: ")
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
    print(f"Wrote encrypted backup for {count} account(s) to {args.path}.")
    return 0


def _cmd_import_backup(args: argparse.Namespace) -> int:
    for warning in backup.unsafe_backup_path_warnings(args.path):
        print(f"Warning: {warning}")
    print("This will import Steam Guard secrets from an encrypted SteamGuardPC backup.")
    if args.replace:
        print("Existing matching accounts will be overwritten with values from the backup.")
    else:
        print("Existing accounts are refused unless --replace is used.")
    if input("Type 'IMPORT BACKUP' to import encrypted backup: ") != "IMPORT BACKUP":
        print("Backup import cancelled.")
        return 1

    passphrase = getpass.getpass("Backup passphrase: ")
    if not passphrase:
        raise ValueError("backup passphrase is required")
    count = backup.import_accounts(args.path, passphrase, replace=args.replace)
    print(f"Imported encrypted backup for {count} account(s).")
    return 0


def _cmd_set_cookies(args: argparse.Namespace) -> int:
    steam_login_secure = os.environ.get("STEAMGUARDPC_STEAM_LOGIN_SECURE")
    sessionid = os.environ.get("STEAMGUARDPC_SESSIONID")
    if steam_login_secure is None or sessionid is None:
        steam_login_secure = getpass.getpass("steamLoginSecure: ")
        sessionid = getpass.getpass("sessionid: ")

    session.save_community_cookies(args.steamid64, steam_login_secure, sessionid)
    print(f"Stored Steam Community cookies for {args.steamid64}.")
    return 0


def _cmd_cookie_guide(args: argparse.Namespace) -> int:
    _print_cookie_guide()
    return 0


def _cmd_find_mafiles(args: argparse.Namespace) -> int:
    candidates = mafile.find_mafile_candidates(args.search_dir or None)
    if not candidates:
        print("No .maFile files found.")
        return 0

    for candidate in candidates:
        print(candidate)
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    print("SteamGuardPC setup")
    print("Secrets are stored in Windows secret storage; config.json stores metadata only.")
    if args.mafile:
        imported, metadata = _import_mafile_path(args.mafile)
        _setup_cookies(
            metadata.steamid64,
            imported_had_cookies=bool(imported.steam_login_secure and imported.sessionid),
            skip_cookies=args.skip_cookies,
        )
    else:
        print("Choose setup method:")
        print("  1. Sign in and add a new mobile authenticator in this app")
        print("  2. Sign in only to store/refresh Steam Community cookies")
        print("  3. Import an existing .maFile (encrypted SDA files supported)")
        choice = input("Setup method [1/2/3]: ").strip()
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

    print("Setup complete.")
    print(f"Next: steamguard-pc code {metadata.steamid64}")
    print(f"Confirmations: steamguard-pc confirmations {metadata.steamid64}")
    return 0


def _cmd_code(args: argparse.Namespace) -> int:
    if args.timestamp is not None and args.steam_time:
        raise ValueError("--timestamp and --steam-time cannot be combined")
    timestamp = steam_time.query_steam_time() if args.steam_time else args.timestamp
    if timestamp is None:
        timestamp = int(time.time())
    shared_secret = storage.get_required_secret(args.steamid64, "shared_secret")
    code = steam_totp(shared_secret, timestamp)
    remaining = seconds_remaining(timestamp)
    print(f"{code} expires_in={remaining}s")
    print("Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.")
    return 0


def _cmd_confirmations(args: argparse.Namespace) -> int:
    _, _, _, current = _load_current_confirmations(args.steamid64)
    if not current:
        print("No pending confirmations.")
        return 0

    for confirmation in current:
        _print_confirmation_row(confirmation)
    return 0


def _cmd_revocation_code(args: argparse.Namespace) -> int:
    metadata = storage.load_accounts().get(args.steamid64)
    if metadata is None:
        raise KeyError(f"missing account metadata for {args.steamid64}")
    print("The Steam Guard revocation code can remove this authenticator from the account.")
    print("It is R followed by five digits, not the seven-digit recovery code Steam requests during sign-in recovery.")
    print("Only reveal it in a private terminal where nobody else can see or record it.")
    expected = f"SHOW REVOCATION CODE {args.steamid64}"
    if input(f"Type {expected!r} to show the revocation code: ") != expected:
        print("Revocation code display cancelled.")
        return 1

    revocation_code = storage.get_required_secret(args.steamid64, "revocation_code")
    _print_revocation_code(metadata, revocation_code)
    return 0

def _cmd_recovery_codes(args: argparse.Namespace) -> int:
    metadata = storage.load_accounts().get(args.steamid64)
    if metadata is None:
        raise KeyError(f"missing account metadata for {args.steamid64}")
    label = _account_label(metadata)
    print("Steam recovery codes are one-time login codes for official Steam recovery prompts.")
    print("Creating a new set may replace older emergency codes. Store the new set offline immediately.")
    expected = f"CREATE RECOVERY CODES {args.steamid64}"
    if input(f"Type {expected!r} to create recovery codes: ") != expected:
        print("Recovery-code creation cancelled.")
        return 1

    access_token, _ = session.refresh_auth_tokens(args.steamid64)
    client = enrollment.EnrollmentClient()
    codes = client.create_emergency_codes(access_token)
    if codes is None:
        confirmation_code = input("Steam recovery-code confirmation code from email or SMS: ").strip()
        if not confirmation_code:
            raise ValueError("Steam recovery-code confirmation code is required")
        codes = client.create_emergency_codes(access_token, confirmation_code)

    print(f"Steam recovery codes for {label}:")
    for code in codes:
        print(code)
    print("Store these one-time codes offline. They are not saved by SteamGuardPC.")
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
        if input(f"Type {expected!r} to approve: ") != expected:
            print("Approval cancelled.")
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
        print(f"Approved {args.confirmation_id}.")
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
        if input(f"Type {expected!r} to cancel: ") != expected:
            print("Cancellation cancelled.")
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
        print(f"Cancelled {args.confirmation_id}.")
        return 0

def _cmd_batch_confirm(args: argparse.Namespace, accept: bool) -> int:
    with operation_lock.account_operation_lock(args.steamid64):
        metadata, identity_secret, community_session, current = _load_current_confirmations(args.steamid64)
        if not current:
            print("No pending confirmations.")
            return 0

        _print_batch_confirmation_review(metadata, community_session, identity_secret, current)
        if accept:
            unsafe = _unsafe_batch_approval_confirmations(current)
            if unsafe:
                print("Batch approval blocked: approve-all only supports Trade and Market listing confirmations.")
                for confirmation in unsafe:
                    print(f"blocked: {confirmation.id}\t{_confirmation_type(confirmation)}\t{confirmation.creator_id or '-'}")
                return 1

        action = "APPROVE" if accept else "CANCEL"
        noun = "approval" if accept else "cancellation"
        expected = f"{action} ALL {len(current)} CONFIRMATIONS {args.steamid64}"
        if input(f"Type {expected!r} to {'approve' if accept else 'cancel'} all listed confirmations: ") != expected:
            print(f"Batch {noun} cancelled.")
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
        print(f"{verb} {len(acted)} confirmations.")
        return 0


def _cmd_approve_all(args: argparse.Namespace) -> int:
    return _cmd_batch_confirm(args, accept=True)


def _cmd_cancel_all(args: argparse.Namespace) -> int:
    return _cmd_batch_confirm(args, accept=False)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steamguard-pc",
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=_HelpFormatter,
    )
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
        description="Run `steamguard-pc COMMAND -h` for command-specific help.",
        required=True,
    )

    setup = subparsers.add_parser(
        "setup",
        help="Guided first-run setup.",
        description="Guided first-run setup.",
        formatter_class=_HelpFormatter,
    )
    setup.add_argument("--mafile", metavar="PATH", help="Import this .maFile directly; encrypted SDA files prompt for the SDA passkey.")
    setup.add_argument("--skip-cookies", action="store_true", help="Skip cookie setup after .maFile import.")
    setup.set_defaults(func=_cmd_setup)

    enroll = subparsers.add_parser(
        "enroll",
        help="Add and finalize a mobile authenticator.",
        description="Add and finalize a mobile authenticator after typed consent.",
        formatter_class=_HelpFormatter,
    )
    enroll.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam account login name. Prompts if omitted.")
    enroll.set_defaults(func=_cmd_enroll)

    login = subparsers.add_parser(
        "login",
        help="Sign in or refresh Community cookies.",
        description="Sign in and store or refresh Steam Community session credentials.",
        formatter_class=_HelpFormatter,
    )
    login.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam account login name. Prompts if omitted.")
    login.set_defaults(func=_cmd_login)

    import_mafile = subparsers.add_parser(
        "import-mafile",
        help="Import a .maFile.",
        description="Import a Steam Desktop Authenticator .maFile into secret storage; encrypted SDA files prompt for the SDA passkey.",
        formatter_class=_HelpFormatter,
    )
    import_mafile.add_argument("path", metavar="PATH", help="Path to a Steam Desktop Authenticator .maFile.")
    import_mafile.set_defaults(func=_cmd_import_mafile)

    export_backup = subparsers.add_parser(
        "export-backup",
        help="Write an encrypted SteamGuardPC backup.",
        description="Write an encrypted backup of stored Steam Guard accounts after typed consent.",
        formatter_class=_HelpFormatter,
    )
    export_backup.add_argument("path", metavar="PATH", help="Destination .sgbak path.")
    export_backup.add_argument("steamid64", nargs="*", metavar="STEAMID64", help="Optional account IDs to export; defaults to all accounts.")
    export_backup.add_argument("--force", action="store_true", help="Overwrite an existing backup file.")
    export_backup.add_argument(
        "--include-revocation-code",
        action="store_true",
        help="Include stored Steam Guard revocation codes after an extra typed warning.",
    )
    export_backup.set_defaults(func=_cmd_export_backup)

    import_backup = subparsers.add_parser(
        "import-backup",
        help="Import an encrypted SteamGuardPC backup.",
        description="Import an encrypted SteamGuardPC backup after typed consent.",
        formatter_class=_HelpFormatter,
    )
    import_backup.add_argument("path", metavar="PATH", help="Encrypted .sgbak path.")
    import_backup.add_argument("--replace", action="store_true", help="Overwrite accounts already stored locally.")
    import_backup.set_defaults(func=_cmd_import_backup)

    code = subparsers.add_parser(
        "code",
        help="Print the current login code.",
        description="Print the current 5-character Steam Guard login code.",
        formatter_class=_HelpFormatter,
    )
    code.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    code.add_argument("--timestamp", type=int, metavar="UNIX_TIME", help="Use a fixed Unix timestamp.")
    code.add_argument("--steam-time", action="store_true", help="Use Steam server time instead of local Windows time.")
    code.set_defaults(func=_cmd_code)

    pending = subparsers.add_parser(
        "confirmations",
        help="List pending confirmations.",
        description="List pending Steam mobile confirmations.",
        formatter_class=_HelpFormatter,
    )
    pending.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    pending.set_defaults(func=_cmd_confirmations)

    approve = subparsers.add_parser(
        "approve",
        help="Approve one confirmation.",
        description="Approve one selected confirmation after typed consent.",
        formatter_class=_HelpFormatter,
    )
    approve.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    approve.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="Confirmation id from `confirmations` output.")
    approve.set_defaults(func=_cmd_approve)

    cancel = subparsers.add_parser(
        "cancel",
        help="Cancel one confirmation.",
        description="Cancel one selected confirmation after typed consent.",
        formatter_class=_HelpFormatter,
    )
    cancel.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    cancel.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="Confirmation id from `confirmations` output.")
    cancel.set_defaults(func=_cmd_cancel)

    approve_all = subparsers.add_parser(
        "approve-all",
        help="Approve all pending confirmations after review.",
        description="Review every pending confirmation and approve the displayed batch after typed consent.",
        formatter_class=_HelpFormatter,
    )
    approve_all.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    approve_all.set_defaults(func=_cmd_approve_all)

    cancel_all = subparsers.add_parser(
        "cancel-all",
        help="Cancel all pending confirmations after review.",
        description="Review every pending confirmation and cancel the displayed batch after typed consent.",
        formatter_class=_HelpFormatter,
    )
    cancel_all.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    cancel_all.set_defaults(func=_cmd_cancel_all)

    revocation_code = subparsers.add_parser(
        "revocation-code",
        help="Reveal the stored R##### code.",
        description="Reveal the stored R##### revocation code after typed consent.",
        formatter_class=_HelpFormatter,
    )
    revocation_code.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    revocation_code.set_defaults(func=_cmd_revocation_code)

    recovery_codes = subparsers.add_parser(
        "recovery-codes",
        help="Create one-time Steam recovery codes.",
        description="Create one-time Steam recovery codes after typed consent.",
        formatter_class=_HelpFormatter,
    )
    recovery_codes.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    recovery_codes.set_defaults(func=_cmd_recovery_codes)

    accounts = subparsers.add_parser(
        "accounts",
        help="List stored accounts.",
        description="List stored account metadata, or delete one stored account after exact typed consent.",
        formatter_class=_HelpFormatter,
    )
    accounts.add_argument("--delete", metavar="STEAMID64", help="Delete this stored account and all stored secrets after exact typed consent.")
    accounts.set_defaults(func=_cmd_accounts)

    find_mafiles = subparsers.add_parser(
        "find-mafiles",
        help="Find .maFile files.",
        description="Search for .maFile files.",
        formatter_class=_HelpFormatter,
    )
    find_mafiles.add_argument("search_dir", nargs="*", metavar="DIR", help="Directory to search.")
    find_mafiles.set_defaults(func=_cmd_find_mafiles)

    cookie_guide = subparsers.add_parser(
        "cookie-guide",
        help="Show manual cookie steps.",
        description="Show browser steps for copying Steam Community cookies.",
        formatter_class=_HelpFormatter,
    )
    cookie_guide.set_defaults(func=_cmd_cookie_guide)

    set_cookies = subparsers.add_parser(
        "set-cookies",
        help="Store Community cookies manually.",
        description="Store steamLoginSecure and sessionid manually.",
        formatter_class=_HelpFormatter,
    )
    set_cookies.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    set_cookies.set_defaults(func=_cmd_set_cookies)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except EXPECTED_ERRORS as exc:
        print(_exception_text(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
