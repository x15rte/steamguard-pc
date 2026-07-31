import base64
import json
import os
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # pragma: no cover - depends on cryptography build
    Argon2id = None  # type: ignore[assignment]

from . import crypto, storage
from .models import AccountMetadata


EXPORT_FORMAT = "steamguard-pc.encrypted-backup"
PLAINTEXT_FORMAT = "steamguard-pc.backup.plain"
BACKUP_VERSION = 2
CIPHER = "aes-256-cbc+hmac-sha512"
KDF_ALGORITHM = "argon2id"
KDF_SALT_BYTES = 32
KDF_LENGTH = 64
KDF_ITERATIONS = 4
KDF_LANES = 4
KDF_MEMORY_COST = 256 * 1024
AES_KEY_BYTES = 32
MAC_KEY_BYTES = 32
AES_CBC_IV_BYTES = 16
MIN_PASSPHRASE_CHARS = 16

_CLOUD_SYNC_DIRS = {
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "iclouddrive",
    "icloud photos",
}


class BackupError(RuntimeError):
    pass


class BackupFormatError(BackupError):
    pass


class BackupDecryptionError(BackupError):
    pass


def unsafe_backup_path_warnings(path: str | Path) -> list[str]:
    selected = Path(path).expanduser()
    try:
        selected = selected.resolve()
    except OSError:
        selected = selected.absolute()

    warnings: list[str] = []
    for parent in (selected.parent, *selected.parents):
        if (parent / ".git").exists():
            warnings.append("Backup path is under a Git checkout; do not commit authenticator backups.")
            break

    parts = {part.casefold() for part in selected.parts}
    if "downloads" in parts:
        warnings.append("Backup path is under Downloads; move it to a private folder.")

    cloud_parts = parts & _CLOUD_SYNC_DIRS
    if cloud_parts:
        warnings.append("Backup path is under a cloud-sync folder; avoid syncing authenticator backups.")

    return warnings


def _malformed() -> None:
    raise BackupFormatError("SteamGuardPC backup is malformed")


def _validate_passphrase(passphrase: str) -> None:
    if not passphrase or not passphrase.strip():
        raise ValueError("backup passphrase is required")
    if len(passphrase) < MIN_PASSPHRASE_CHARS:
        raise ValueError(f"backup passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")


def _kdf_header(salt: bytes) -> dict[str, object]:
    return {
        "algorithm": KDF_ALGORITHM,
        "salt": base64.b64encode(salt).decode("ascii"),
        "length": KDF_LENGTH,
        "iterations": KDF_ITERATIONS,
        "lanes": KDF_LANES,
        "memory_cost": KDF_MEMORY_COST,
    }


def _string_field(raw: Mapping[str, object], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value:
        _malformed()
    return value


def _optional_string_field(raw: Mapping[str, object], field: str) -> str | None:
    value = raw.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        _malformed()
    return value


def _int_field(raw: Mapping[str, object], field: str) -> int:
    value = raw.get(field)
    if not isinstance(value, int):
        _malformed()
    return value


def _decode_base64_field(raw: Mapping[str, object], field: str, expected_length: int | None = None) -> bytes:
    value = _string_field(raw, field)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise BackupFormatError("SteamGuardPC backup is malformed") from exc
    if expected_length is not None and len(decoded) != expected_length:
        _malformed()
    return decoded


def _derive_keys(passphrase: str, kdf_header: Mapping[str, object]) -> tuple[bytes, bytes]:
    if Argon2id is None:
        raise BackupError("Argon2id KDF is unavailable in this cryptography build")

    if kdf_header.get("algorithm") != KDF_ALGORITHM:
        _malformed()

    salt = _decode_base64_field(kdf_header, "salt", KDF_SALT_BYTES)
    length = _int_field(kdf_header, "length")
    iterations = _int_field(kdf_header, "iterations")
    lanes = _int_field(kdf_header, "lanes")
    memory_cost = _int_field(kdf_header, "memory_cost")
    if (
        length != KDF_LENGTH
        or iterations != KDF_ITERATIONS
        or lanes != KDF_LANES
        or memory_cost != KDF_MEMORY_COST
    ):
        _malformed()

    try:
        derived = Argon2id(
            salt=salt,
            length=length,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_cost,
        ).derive(passphrase.encode("utf-8"))
    except UnsupportedAlgorithm as exc:
        raise BackupError("Argon2id KDF is unavailable in this cryptography build") from exc
    return derived[:AES_KEY_BYTES], derived[AES_KEY_BYTES : AES_KEY_BYTES + MAC_KEY_BYTES]


def _authenticated_payload(wrapper: Mapping[str, object]) -> bytes:
    authenticated = {
        "format": wrapper["format"],
        "version": wrapper["version"],
        "cipher": wrapper["cipher"],
        "kdf": wrapper["kdf"],
        "iv": wrapper["iv"],
        "ciphertext": wrapper["ciphertext"],
    }
    return json.dumps(authenticated, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_sha512(mac_key: bytes, payload: bytes) -> bytes:
    hmac = crypto_hmac.HMAC(mac_key, hashes.SHA512())
    hmac.update(payload)
    return hmac.finalize()


def _verify_hmac_sha512(mac_key: bytes, payload: bytes, expected: bytes) -> None:
    hmac = crypto_hmac.HMAC(mac_key, hashes.SHA512())
    hmac.update(payload)
    hmac.verify(expected)


def _encrypt_aes256_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise BackupDecryptionError("backup passphrase is incorrect or backup file is corrupted") from exc


def _account_to_backup(metadata: AccountMetadata) -> dict[str, object]:
    secrets: dict[str, str] = {}
    for field in storage.SECRET_FIELDS:
        value = storage.get_secret(metadata.steamid64, field)
        if value is not None:
            secrets[field] = value

    return {
        "steamid64": metadata.steamid64,
        "account_name": metadata.account_name,
        "device_id": metadata.device_id,
        "last_imported_at": metadata.last_imported_at,
        "secrets": secrets,
    }


def _plain_backup(accounts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "format": PLAINTEXT_FORMAT,
        "version": BACKUP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "accounts": accounts,
    }


def export_accounts(
    path: str | Path,
    passphrase: str,
    steamid64s: Sequence[str] | None = None,
    overwrite: bool = False,
) -> int:
    _validate_passphrase(passphrase)

    metadata_by_id = storage.load_accounts()
    if steamid64s is None:
        selected_ids = sorted(metadata_by_id)
    else:
        selected_ids = list(steamid64s)
        if not selected_ids:
            raise ValueError("no accounts selected for backup")

    selected_accounts: list[dict[str, object]] = []
    for steamid64 in selected_ids:
        metadata = metadata_by_id.get(steamid64)
        if metadata is None:
            raise KeyError(f"missing account metadata for {steamid64}")
        selected_accounts.append(_account_to_backup(metadata))

    if not selected_accounts:
        raise ValueError("no accounts selected for backup")

    output_path = Path(path)
    if output_path.exists() and not overwrite:
        raise BackupError(f"backup file already exists: {path}")

    salt = os.urandom(KDF_SALT_BYTES)
    iv = os.urandom(AES_CBC_IV_BYTES)
    kdf = _kdf_header(salt)
    encryption_key, mac_key = _derive_keys(passphrase, kdf)
    plaintext = json.dumps(_plain_backup(selected_accounts), sort_keys=True, separators=(",", ":")).encode("utf-8")
    wrapper: dict[str, object] = {
        "format": EXPORT_FORMAT,
        "version": BACKUP_VERSION,
        "cipher": CIPHER,
        "kdf": kdf,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(_encrypt_aes256_cbc(plaintext, encryption_key, iv)).decode("ascii"),
    }
    wrapper["hmac"] = base64.b64encode(_hmac_sha512(mac_key, _authenticated_payload(wrapper))).decode("ascii")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(wrapper, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(selected_accounts)


def _load_json_file(path: str | Path) -> Mapping[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupFormatError("SteamGuardPC backup is malformed") from exc
    if not isinstance(raw, dict):
        _malformed()
    return raw


def _decode_wrapper(path: str | Path) -> tuple[Mapping[str, object], bytes, bytes, bytes]:
    wrapper = _load_json_file(path)
    if (
        wrapper.get("format") != EXPORT_FORMAT
        or wrapper.get("version") != BACKUP_VERSION
        or wrapper.get("cipher") != CIPHER
    ):
        _malformed()

    kdf = wrapper.get("kdf")
    if not isinstance(kdf, dict):
        _malformed()
    if kdf.get("algorithm") != KDF_ALGORITHM:
        _malformed()

    iv = _decode_base64_field(wrapper, "iv", AES_CBC_IV_BYTES)
    ciphertext = _decode_base64_field(wrapper, "ciphertext")
    expected_hmac = _decode_base64_field(wrapper, "hmac", 64)
    if len(ciphertext) == 0 or len(ciphertext) % AES_CBC_IV_BYTES != 0:
        _malformed()
    return wrapper, iv, ciphertext, expected_hmac


def _decrypt_plaintext(path: str | Path, passphrase: str) -> Mapping[str, Any]:
    wrapper, iv, ciphertext, expected_hmac = _decode_wrapper(path)
    encryption_key, mac_key = _derive_keys(passphrase, wrapper["kdf"])
    try:
        _verify_hmac_sha512(mac_key, _authenticated_payload(wrapper), expected_hmac)
    except InvalidSignature as exc:
        raise BackupDecryptionError("backup passphrase is incorrect or backup file is corrupted") from exc

    plaintext = _decrypt_aes256_cbc(ciphertext, encryption_key, iv)
    try:
        plain = json.loads(plaintext.decode("utf-8"))
    except (JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupFormatError("SteamGuardPC backup is malformed") from exc
    if not isinstance(plain, dict):
        _malformed()
    if plain.get("format") != PLAINTEXT_FORMAT or plain.get("version") != BACKUP_VERSION:
        _malformed()
    accounts = plain.get("accounts")
    if not isinstance(accounts, list):
        _malformed()
    if not accounts:
        raise BackupFormatError("SteamGuardPC backup contains no accounts")
    return plain


def _account_from_backup(raw: object) -> tuple[AccountMetadata, dict[str, str]]:
    if not isinstance(raw, dict):
        _malformed()

    steamid64 = _string_field(raw, "steamid64")
    metadata = AccountMetadata(
        steamid64=steamid64,
        account_name=_optional_string_field(raw, "account_name"),
        device_id=_optional_string_field(raw, "device_id"),
        last_imported_at=_optional_string_field(raw, "last_imported_at"),
    )

    secrets_raw = raw.get("secrets")
    if not isinstance(secrets_raw, dict):
        _malformed()

    secrets: dict[str, str] = {}
    for field, value in secrets_raw.items():
        if not isinstance(field, str) or field not in storage.SECRET_FIELDS:
            _malformed()
        if not isinstance(value, str) or not value:
            _malformed()
        if field in {"shared_secret", "identity_secret"}:
            try:
                crypto.validate_base64_secret(value, field)
            except ValueError as exc:
                raise BackupFormatError("SteamGuardPC backup is malformed") from exc
        secrets[field] = value
    return metadata, secrets


def import_accounts(path: str | Path, passphrase: str, replace: bool = False) -> int:
    _validate_passphrase(passphrase)

    plain = _decrypt_plaintext(path, passphrase)
    imported = [_account_from_backup(account) for account in plain["accounts"]]

    existing = storage.load_accounts()
    if not replace:
        for metadata, _ in imported:
            if metadata.steamid64 in existing:
                raise BackupError(
                    f"account {metadata.steamid64} already exists; rerun with --replace to overwrite it"
                )

    for metadata, secrets in imported:
        for field, value in secrets.items():
            storage.put_secret(metadata.steamid64, field, value)
        storage.upsert_account(metadata)

    return len(imported)
