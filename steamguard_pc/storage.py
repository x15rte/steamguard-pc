import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .models import AccountMetadata, ImportedSteamGuard


SERVICE = "SteamGuardPC"
CONFIG_SCHEMA_VERSION = 1
SECRET_FIELDS = {
    "shared_secret",
    "identity_secret",
    "revocation_code",
    "refresh_token",
    "access_token",
    "steamLoginSecure",
    "sessionid",
    "serial_number",
    "token_gid",
    "uri",
}


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


def config_dir() -> Path:
    configured = os.environ.get("STEAMGUARDPC_CONFIG_DIR")
    if configured:
        return Path(configured)

    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "SteamGuardPC"

    return Path.home() / "AppData" / "Roaming" / "SteamGuardPC"


def config_path() -> Path:
    return config_dir() / "config.json"


def secret_name(steamid64: str, field: str) -> str:
    if field not in SECRET_FIELDS:
        raise ValueError(f"unsupported secret field: {field}")
    return f"{steamid64}:{field}"


def put_secret(steamid64: str, field: str, value: str) -> None:
    ensure_secret_storage_available()
    try:
        keyring.set_password(SERVICE, secret_name(steamid64, field), value)
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


def get_secret(steamid64: str, field: str) -> str | None:
    ensure_secret_storage_available()
    try:
        return keyring.get_password(SERVICE, secret_name(steamid64, field))
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


def delete_secret(steamid64: str, field: str) -> None:
    ensure_secret_storage_available()
    try:
        keyring.delete_password(SERVICE, secret_name(steamid64, field))
    except KeyringError as exc:
        raise SecretStorageUnavailable("Windows secret storage is unavailable") from exc


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
    path.parent.mkdir(parents=True, exist_ok=True)
    account_rows = []
    for metadata in sorted(accounts.values(), key=lambda account: account.steamid64):
        row = asdict(metadata)
        for field in SECRET_FIELDS:
            row.pop(field, None)
        account_rows.append(row)

    payload = {
        "version": CONFIG_SCHEMA_VERSION,
        "accounts": account_rows,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def upsert_account(metadata: AccountMetadata) -> None:
    accounts = load_accounts()
    accounts[metadata.steamid64] = metadata
    save_accounts(accounts)


def store_imported_guard(imported: ImportedSteamGuard) -> AccountMetadata:
    put_secret(imported.steamid64, "shared_secret", imported.shared_secret)
    put_secret(imported.steamid64, "identity_secret", imported.identity_secret)

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
            put_secret(imported.steamid64, field, value)

    metadata = AccountMetadata(
        steamid64=imported.steamid64,
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
