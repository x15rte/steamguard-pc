import base64
import json

import pytest

from steamguard_pc import backup, storage
from steamguard_pc.models import AccountMetadata


STEAMID64 = "76561197960287930"
OTHER_STEAMID64 = "76561197960287931"
SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
REVOCATION_CODE = "REVOCATION_CODE"
STEAM_LOGIN_SECURE = "STEAM_LOGIN_SECURE"
SESSIONID = "SESSIONID"
PASSPHRASE = "correct horse battery staple"

SEEDED_SECRETS = {
    "shared_secret": SHARED_SECRET,
    "identity_secret": IDENTITY_SECRET,
    "revocation_code": REVOCATION_CODE,
    "steamLoginSecure": STEAM_LOGIN_SECURE,
    "sessionid": SESSIONID,
}


def _use_fast_kdf(monkeypatch):
    monkeypatch.setattr(backup, "KDF_MEMORY_COST", 8 * backup.KDF_LANES)
    monkeypatch.setattr(backup, "KDF_ITERATIONS", 1)


def _seed_account() -> AccountMetadata:
    metadata = AccountMetadata(
        steamid64=STEAMID64,
        account_name="fixture",
        device_id="android:fixture",
        last_imported_at="2026-07-31T00:00:00Z",
    )
    storage.upsert_account(metadata)
    for field, value in SEEDED_SECRETS.items():
        storage.put_secret(STEAMID64, field, value)
    return metadata


def test_export_backup_encrypts_secret_values(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"

    assert backup.export_accounts(path, PASSPHRASE) == 1

    raw_text = path.read_text(encoding="utf-8")
    wrapper = json.loads(raw_text)
    assert wrapper["format"] == backup.EXPORT_FORMAT
    assert wrapper["version"] == backup.BACKUP_VERSION
    assert wrapper["cipher"] == backup.CIPHER
    assert wrapper["kdf"]["algorithm"] == backup.KDF_ALGORITHM
    assert "token" not in wrapper
    assert all(field in wrapper for field in ("iv", "ciphertext", "hmac"))
    for secret in SEEDED_SECRETS.values():
        assert secret not in raw_text


def test_import_backup_restores_metadata_and_secrets(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    metadata = _seed_account()
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE)
    keyring_store.clear()
    storage.save_accounts({})

    assert backup.import_accounts(path, PASSPHRASE) == 1

    assert storage.load_accounts()[STEAMID64] == metadata
    for field, value in SEEDED_SECRETS.items():
        expected = None if field == "revocation_code" else value
        assert storage.get_secret(STEAMID64, field) == expected


def test_export_backup_can_include_revocation_code_with_opt_in(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE, include_revocation_code=True)
    keyring_store.clear()
    storage.save_accounts({})

    assert backup.import_accounts(path, PASSPHRASE) == 1

    assert storage.get_secret(STEAMID64, "revocation_code") == REVOCATION_CODE


def test_import_backup_rejects_wrong_passphrase(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE)

    with pytest.raises(
        backup.BackupDecryptionError,
        match="^backup passphrase is incorrect or backup file is corrupted$",
    ):
        backup.import_accounts(path, "wrong passphrase")

def test_import_backup_rejects_tampered_hmac(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE)
    wrapper = json.loads(path.read_text(encoding="utf-8"))
    wrapper["hmac"] = base64.b64encode(b"\0" * 64).decode("ascii")
    path.write_text(json.dumps(wrapper), encoding="utf-8")

    with pytest.raises(
        backup.BackupDecryptionError,
        match="^backup passphrase is incorrect or backup file is corrupted$",
    ):
        backup.import_accounts(path, PASSPHRASE)


def test_export_backup_rejects_short_passphrase(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()

    with pytest.raises(ValueError, match="^backup passphrase must be at least 16 characters$"):
        backup.export_accounts(tmp_path / "steamguard.sgbak", "short pass")


def test_import_backup_refuses_existing_account_without_replace(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE)

    with pytest.raises(backup.BackupError) as excinfo:
        backup.import_accounts(path, PASSPHRASE)

    assert str(excinfo.value) == f"account {STEAMID64} already exists; rerun with --replace to overwrite it"


def test_import_backup_conflict_callback_can_skip_existing_and_import_new(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    metadata = _seed_account()
    other_metadata = AccountMetadata(
        steamid64=OTHER_STEAMID64,
        account_name="other",
        device_id="android:other",
        last_imported_at="2026-07-31T00:00:00Z",
    )
    storage.upsert_account(other_metadata)
    storage.put_secret(OTHER_STEAMID64, "shared_secret", SHARED_SECRET)
    storage.put_secret(OTHER_STEAMID64, "identity_secret", IDENTITY_SECRET)
    path = tmp_path / "steamguard.sgbak"
    backup.export_accounts(path, PASSPHRASE)

    local_metadata = AccountMetadata(
        steamid64=STEAMID64,
        account_name="local",
        device_id="android:local",
        last_imported_at="2026-08-01T00:00:00Z",
    )
    keyring_store.clear()
    storage.save_accounts({STEAMID64: local_metadata})
    storage.put_secret(STEAMID64, "shared_secret", "LOCAL_SHARED_SECRET")
    prompted: list[AccountMetadata] = []
    imported: list[AccountMetadata] = []

    def skip_existing(account: AccountMetadata) -> bool:
        prompted.append(account)
        return False

    assert backup.import_accounts(
        path,
        PASSPHRASE,
        should_overwrite_account=skip_existing,
        on_imported_account=imported.append,
    ) == 1

    accounts = storage.load_accounts()
    assert prompted == [metadata]
    assert imported == [other_metadata]
    assert accounts[STEAMID64] == local_metadata
    assert accounts[OTHER_STEAMID64] == other_metadata
    assert storage.get_secret(STEAMID64, "shared_secret") == "LOCAL_SHARED_SECRET"
    assert storage.get_secret(OTHER_STEAMID64, "shared_secret") == SHARED_SECRET


def test_export_backup_refuses_overwrite_without_force(monkeypatch, tmp_path, keyring_store):
    _use_fast_kdf(monkeypatch)
    _seed_account()
    path = tmp_path / "steamguard.sgbak"
    path.write_text("existing", encoding="utf-8")

    with pytest.raises(backup.BackupError) as excinfo:
        backup.export_accounts(path, PASSPHRASE, overwrite=False)

    assert str(excinfo.value) == f"backup file already exists: {path}"


def test_account_from_backup_rejects_invalid_steamid64():
    with pytest.raises(backup.BackupFormatError) as excinfo:
        backup._account_from_backup({"steamid64": "..\\..\\evil", "secrets": {}})

    assert str(excinfo.value) == "steamguard-pc backup is malformed"
