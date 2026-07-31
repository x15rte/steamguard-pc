import argparse
import getpass
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

from . import auth, confirmations, enrollment, mafile, session, storage
from .auth import GuardAction, LoginResult, SteamAuthError
from .confirmations import Confirmation, ConfirmationError
from .crypto import generate_device_id, seconds_remaining, steam_totp
from .enrollment import EnrollmentError
from .session import SessionExpiredError
from .storage import SecretStorageUnavailable


EXPECTED_ERRORS = (
    ValueError,
    KeyError,
    SecretStorageUnavailable,
    SessionExpiredError,
    ConfirmationError,
    SteamAuthError,
    EnrollmentError,
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

It stores Steam Guard authenticators, revocation codes, session tokens, and
Steam Community cookies in keyring-backed secret storage. It can enroll a new
authenticator, import a decrypted .maFile, generate offline login codes,
refresh sessions, and approve or cancel one mobile confirmation at a time.
"""


HELP_EPILOG = """\
Common workflows:
  steamguard-pc setup
      Guided first run. Choose enrollment, login-only, or .maFile import.

  steamguard-pc enroll ACCOUNT_NAME
      Add a new mobile authenticator. Requires ADD AUTHENTICATOR <steamid64>,
      stores the new secrets before validation, shows the R##### revocation code
      when available, then asks for Steam's email/SMS activation code.

  steamguard-pc login ACCOUNT_NAME
      Sign in or refresh the Steam Community session. If a shared_secret is
      already stored, the required mobile code is generated without printing it.

  steamguard-pc code STEAMID64
      Print the current 5-character login code and seconds remaining.

  steamguard-pc confirmations STEAMID64
      List pending mobile confirmations.

  steamguard-pc approve STEAMID64 CONFIRMATION_ID
  steamguard-pc cancel  STEAMID64 CONFIRMATION_ID
      Show the selected confirmation, require APPROVE/CANCEL <id>, then verify
      the target disappeared after Steam accepts the action.

  steamguard-pc revocation-code STEAMID64
      Reveal the stored R##### revocation code only after typing
      SHOW REVOCATION CODE <steamid64>. This code can remove the authenticator.

Safety notes:
  - Secrets are stored via keyring; no plaintext secret fallback is used.
  - .maFile imports must be decrypted first and should not be kept in Git,
    Downloads, or cloud-sync folders.
  - Keep Windows time synchronized; Steam Guard codes are time based.

Run `steamguard-pc COMMAND -h` for command-specific options.
Full usage guide: USAGE.md
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


def _print_confirmation_detail(confirmation: Confirmation) -> None:
    print(f"id: {confirmation.id}")
    print(f"type: {_confirmation_type(confirmation)}")
    print(f"creator_id: {confirmation.creator_id or '-'}")
    print(f"headline: {confirmation.headline or '-'}")
    print(f"summary: {_summary_text(confirmation.summary)}")


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


def _confirmation_context(steamid64: str) -> tuple[storage.AccountMetadata, str, object]:
    metadata = _account_metadata(steamid64)
    identity_secret = storage.get_required_secret(steamid64, "identity_secret")
    community_session = session.get_community_session(steamid64)
    return metadata, identity_secret, community_session


def _find_current_confirmation(steamid64: str, confirmation_id: str) -> tuple[storage.AccountMetadata, str, object, Confirmation]:
    metadata, identity_secret, community_session = _confirmation_context(steamid64)
    current = confirmations.get_confirmations(
        community_session,
        steamid64,
        metadata.device_id or "",
        identity_secret,
    )
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

    imported = mafile.load_mafile(path)
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
        print("Found decrypted .maFile candidates:")
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
    choice = input("Path to decrypted .maFile (blank to cancel): ").strip()
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
    storage.put_secret(result.steamid64, "access_token", result.access_token)
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

    client = enrollment.EnrollmentClient()
    add_result = client.add_authenticator(
        result.access_token,
        result.steamid64,
        account_name=result.account_name,
        device_id=metadata.device_id,
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
    print("Steam may send the activation code by email or SMS. A phone number is not required when Steam offers its no-phone email path.")
    resend_phrase = f"SEND ACTIVATION EMAIL {result.steamid64}"
    print(f"If no code arrives, type {resend_phrase!r} instead of the code to ask Steam to email another activation code.")
    activation_code = input("Steam activation code from email or SMS: ").strip()
    if activation_code == resend_phrase:
        client.send_activation_email(result.access_token, result.steamid64)
        print("Requested an activation-code email from Steam.")
        activation_code = input("Steam activation code from email or SMS: ").strip()
    if not activation_code:
        raise ValueError("Steam activation code is required")
    client.finalize_authenticator(
        result.access_token,
        result.steamid64,
        imported.shared_secret,
        activation_code,
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

def _cmd_accounts(args: argparse.Namespace) -> int:
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
        print("  3. Import an existing decrypted .maFile")
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
    timestamp = args.timestamp if args.timestamp is not None else int(time.time())
    shared_secret = storage.get_required_secret(args.steamid64, "shared_secret")
    code = steam_totp(shared_secret, timestamp)
    remaining = seconds_remaining(timestamp)
    print(f"{code} expires_in={remaining}s")
    print("Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.")
    return 0


def _cmd_confirmations(args: argparse.Namespace) -> int:
    metadata, identity_secret, community_session = _confirmation_context(args.steamid64)
    current = confirmations.get_confirmations(
        community_session,
        args.steamid64,
        metadata.device_id or "",
        identity_secret,
    )
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


def _cmd_approve(args: argparse.Namespace) -> int:
    metadata, identity_secret, community_session, target = _find_current_confirmation(
        args.steamid64,
        args.confirmation_id,
    )
    _print_confirmation_detail(target)
    expected = f"APPROVE {args.confirmation_id}"
    if input(f"Type {expected!r} to approve: ") != expected:
        print("Approval cancelled.")
        return 1

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
    metadata, identity_secret, community_session, target = _find_current_confirmation(
        args.steamid64,
        args.confirmation_id,
    )
    _print_confirmation_detail(target)
    expected = f"CANCEL {args.confirmation_id}"
    if input(f"Type {expected!r} to cancel: ") != expected:
        print("Approval cancelled.")
        return 1

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
        description=(
            "Guided first-run setup. Choose authenticator enrollment, login-only\n"
            "session refresh, or decrypted .maFile import."
        ),
        formatter_class=_HelpFormatter,
    )
    setup.add_argument("--mafile", metavar="PATH", help="Import this decrypted .maFile directly instead of asking setup questions.")
    setup.add_argument("--skip-cookies", action="store_true", help="After .maFile import, do not prompt to store Steam Community cookies.")
    setup.set_defaults(func=_cmd_setup)

    enroll = subparsers.add_parser(
        "enroll",
        help="Add a mobile authenticator and complete validation.",
        description=(
            "Add and finalize a new Steam mobile authenticator.\n"
            "Requires exact typed consent, stores generated secrets before validation,\n"
            "shows the R##### revocation code when Steam returns one, then asks for\n"
            "Steam's email/SMS activation code."
        ),
        formatter_class=_HelpFormatter,
    )
    enroll.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam account login name. Prompts if omitted.")
    enroll.set_defaults(func=_cmd_enroll)

    login = subparsers.add_parser(
        "login",
        help="Sign in or refresh the Steam Community session.",
        description=(
            "Sign in to Steam, handle Steam Guard challenges, and store or refresh\n"
            "session tokens and Steam Community cookies. If a shared_secret is already\n"
            "stored, the required mobile code is generated without printing it."
        ),
        formatter_class=_HelpFormatter,
    )
    login.add_argument("account_name", nargs="?", metavar="ACCOUNT_NAME", help="Steam account login name. Prompts if omitted.")
    login.set_defaults(func=_cmd_login)

    import_mafile = subparsers.add_parser(
        "import-mafile",
        help="Import a decrypted .maFile into secret storage.",
        description=(
            "Import a decrypted Steam Desktop Authenticator-compatible .maFile.\n"
            "Secrets are stored in keyring and are never printed."
        ),
        formatter_class=_HelpFormatter,
    )
    import_mafile.add_argument("path", metavar="PATH", help="Path to a decrypted .maFile JSON export.")
    import_mafile.set_defaults(func=_cmd_import_mafile)

    code = subparsers.add_parser(
        "code",
        help="Print the current Steam Guard login code.",
        description=(
            "Generate the current 5-character Steam Guard login code offline.\n"
            "Uses the stored shared_secret and prints seconds remaining."
        ),
        formatter_class=_HelpFormatter,
    )
    code.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    code.add_argument("--timestamp", type=int, metavar="UNIX_TIME", help="Use a fixed Unix timestamp for deterministic troubleshooting/tests.")
    code.set_defaults(func=_cmd_code)

    pending = subparsers.add_parser(
        "confirmations",
        help="List pending mobile confirmations.",
        description=(
            "List pending Steam mobile confirmations.\n"
            "Uses the stored identity_secret and Steam Community cookies."
        ),
        formatter_class=_HelpFormatter,
    )
    pending.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    pending.set_defaults(func=_cmd_confirmations)

    approve = subparsers.add_parser(
        "approve",
        help="Approve one confirmation after exact typed consent.",
        description=(
            "Approve exactly one selected confirmation.\n"
            "Prints target details, requires `APPROVE <confirmation_id>`, and reports\n"
            "success only after the target disappears from a refreshed list."
        ),
        formatter_class=_HelpFormatter,
    )
    approve.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    approve.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="Confirmation id from `confirmations` output.")
    approve.set_defaults(func=_cmd_approve)

    cancel = subparsers.add_parser(
        "cancel",
        help="Cancel one confirmation after exact typed consent.",
        description=(
            "Cancel exactly one selected confirmation.\n"
            "Prints target details, requires `CANCEL <confirmation_id>`, and reports\n"
            "success only after the target disappears from a refreshed list."
        ),
        formatter_class=_HelpFormatter,
    )
    cancel.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    cancel.add_argument("confirmation_id", metavar="CONFIRMATION_ID", help="Confirmation id from `confirmations` output.")
    cancel.set_defaults(func=_cmd_cancel)

    revocation_code = subparsers.add_parser(
        "revocation-code",
        help="Reveal the stored R##### revocation code after consent.",
        description=(
            "Reveal the stored Steam Guard R##### revocation code after exact typed consent.\n"
            "This code can remove the authenticator and is not Steam's seven-digit\n"
            "website sign-in recovery code."
        ),
        formatter_class=_HelpFormatter,
    )
    revocation_code.add_argument("steamid64", metavar="STEAMID64", help="SteamID64 for the stored account.")
    revocation_code.set_defaults(func=_cmd_revocation_code)

    accounts = subparsers.add_parser(
        "accounts",
        help="List stored account metadata.",
        description=(
            "List Steam accounts known to SteamGuardPC.\n"
            "Prints metadata only; secrets are never printed."
        ),
        formatter_class=_HelpFormatter,
    )
    accounts.set_defaults(func=_cmd_accounts)

    find_mafiles = subparsers.add_parser(
        "find-mafiles",
        help="Search for .maFile candidates.",
        description=(
            "Search common locations or supplied directories for .maFile files.\n"
            "Useful before importing an existing authenticator."
        ),
        formatter_class=_HelpFormatter,
    )
    find_mafiles.add_argument("search_dir", nargs="*", metavar="DIR", help="Directory to search. Defaults to common SDA-style locations.")
    find_mafiles.set_defaults(func=_cmd_find_mafiles)

    cookie_guide = subparsers.add_parser(
        "cookie-guide",
        help="Show manual cookie-copying steps.",
        description=(
            "Print fallback browser instructions for manually copying\n"
            "steamLoginSecure and sessionid. Prefer `login` when possible."
        ),
        formatter_class=_HelpFormatter,
    )
    cookie_guide.set_defaults(func=_cmd_cookie_guide)

    set_cookies = subparsers.add_parser(
        "set-cookies",
        help="Store Steam Community cookies manually.",
        description=(
            "Store steamLoginSecure and sessionid for an account.\n"
            "Manual fallback only; prefer `login` when possible."
        ),
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
