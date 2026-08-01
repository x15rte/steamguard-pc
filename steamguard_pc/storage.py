import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from .models import AccountMetadata, ImportedSteamGuard


APP_NAME = "steamguard-pc"
SERVICE = APP_NAME
CONFIG_ENV_VAR = "STEAMGUARD_PC_CONFIG_DIR"
CONFIG_SCHEMA_VERSION = 1
STEAMID64_MIN_LENGTH = 16
STEAMID64_MAX_LENGTH = 20
STEAMID64_MAX_VALUE = 0xFFFFFFFFFFFFFFFF
SECRET_FIELDS = {
    "shared_secret",
    "identity_secret",
    "revocation_code",
    "refresh_token",
    "access_token",
    "access_token_obtained_at",
    "steamLoginSecure",
    "sessionid",
    "serial_number",
    "token_gid",
    "uri",
}

AUTHENTICATOR_SECRET_FIELDS = (
    "shared_secret",
    "identity_secret",
    "revocation_code",
    "serial_number",
    "token_gid",
    "uri",
)


class SecretStorageUnavailable(RuntimeError):
    pass


def ensure_secret_storage_available() -> None:
    try:
        backend = keyring.get_keyring()
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc
    backend_name = f"{backend.__class__.__module__}.{backend.__class__.__name__}"
    if backend_name == "keyring.backends.null.Keyring":
        raise SecretStorageUnavailable("Windows secret storage is unavailable; keyring is using the null backend")


def _default_config_base() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata)
    return Path.home() / "AppData" / "Roaming"


def config_dir() -> Path:
    configured = os.environ.get(CONFIG_ENV_VAR)
    if configured:
        return Path(configured)
    return _default_config_base() / APP_NAME




def config_path() -> Path:
    return config_dir() / "config.json"

def validate_steamid64(steamid64: str) -> str:
    if (
        isinstance(steamid64, str)
        and steamid64.isascii()
        and steamid64.isdecimal()
        and STEAMID64_MIN_LENGTH <= len(steamid64) <= STEAMID64_MAX_LENGTH
        and int(steamid64) <= STEAMID64_MAX_VALUE
    ):
        return steamid64
    raise ValueError(f"invalid SteamID64: {steamid64!a}")


def secret_name(steamid64: str, field: str) -> str:
    if field not in SECRET_FIELDS:
        raise ValueError(f"unsupported secret field: {field}")
    steamid64 = validate_steamid64(steamid64)
    return f"{steamid64}:{field}"


def _set_password(service: str, name: str, value: str) -> None:
    try:
        keyring.set_password(service, name, value)
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


def _get_password(service: str, name: str) -> str | None:
    try:
        return keyring.get_password(service, name)
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


def _delete_password(service: str, name: str) -> None:
    try:
        keyring.delete_password(service, name)
    except PasswordDeleteError:
        pass
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


def put_secret(steamid64: str, field: str, value: str) -> None:
    ensure_secret_storage_available()
    _set_password(SERVICE, secret_name(steamid64, field), value)


def get_secret(steamid64: str, field: str) -> str | None:
    ensure_secret_storage_available()
    return _get_password(SERVICE, secret_name(steamid64, field))


def delete_secret(steamid64: str, field: str) -> None:
    ensure_secret_storage_available()
    _delete_password(SERVICE, secret_name(steamid64, field))


def load_accounts() -> dict[str, AccountMetadata]:
    path = config_path()
    if not path.exists():
        return {}

    data = json.loads(path.read_text(encoding="utf-8"))
    accounts: dict[str, AccountMetadata] = {}
    for item in data.get("accounts", []):
        if not isinstance(item, dict):
            continue
        steamid64 = item.get("steamid64")
        if not isinstance(steamid64, str) or not steamid64:
            continue
        try:
            steamid64 = validate_steamid64(steamid64)
        except ValueError:
            continue
        accounts[steamid64] = AccountMetadata(
            steamid64=steamid64,
            account_name=item.get("account_name") if isinstance(item.get("account_name"), str) else None,
            device_id=item.get("device_id") if isinstance(item.get("device_id"), str) else None,
            last_imported_at=(
                item.get("last_imported_at")
                if isinstance(item.get("last_imported_at"), str)
                else None
            ),
        )
    return accounts


def save_accounts(accounts: dict[str, AccountMetadata]) -> None:
    path = config_path()
    account_rows = []
    for metadata in sorted(accounts.values(), key=lambda account: account.steamid64):
        steamid64 = validate_steamid64(metadata.steamid64)
        row = asdict(metadata)
        row["steamid64"] = steamid64
        for field in SECRET_FIELDS:
            row.pop(field, None)
        account_rows.append(row)

    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "version": CONFIG_SCHEMA_VERSION,
        "accounts": account_rows,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def upsert_account(metadata: AccountMetadata) -> None:
    steamid64 = validate_steamid64(metadata.steamid64)
    accounts = load_accounts()
    accounts[steamid64] = metadata
    save_accounts(accounts)


def delete_account(steamid64: str) -> AccountMetadata:
    steamid64 = validate_steamid64(steamid64)
    accounts = load_accounts()
    metadata = accounts.pop(steamid64, None)
    if metadata is None:
        raise KeyError(f"missing account metadata for {steamid64}")

    for field in SECRET_FIELDS:
        delete_secret(steamid64, field)
    save_accounts(accounts)
    return metadata

def delete_authenticator_secrets(steamid64: str) -> None:
    steamid64 = validate_steamid64(steamid64)
    accounts = load_accounts()
    if steamid64 not in accounts:
        raise KeyError(f"missing account metadata for {steamid64}")

    for field in AUTHENTICATOR_SECRET_FIELDS:
        delete_secret(steamid64, field)


def store_imported_guard(imported: ImportedSteamGuard) -> AccountMetadata:
    steamid64 = validate_steamid64(imported.steamid64)
    put_secret(steamid64, "shared_secret", imported.shared_secret)
    put_secret(steamid64, "identity_secret", imported.identity_secret)

    optional_secrets = {
        "revocation_code": imported.revocation_code,
        "refresh_token": imported.refresh_token,
        "access_token": imported.access_token,
        "steamLoginSecure": imported.steam_login_secure,
        "sessionid": imported.sessionid,
        "serial_number": imported.serial_number,
        "token_gid": imported.token_gid,
        "uri": imported.uri,
    }
    for field, value in optional_secrets.items():
        if value:
            put_secret(steamid64, field, value)

    metadata = AccountMetadata(
        steamid64=steamid64,
        account_name=imported.account_name,
        device_id=imported.device_id,
        last_imported_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    upsert_account(metadata)
    return metadata


def get_required_secret(steamid64: str, field: str) -> str:
    value = get_secret(steamid64, field)
    if value is None:
        raise KeyError(f"missing {field} for {steamid64}")
    return value
