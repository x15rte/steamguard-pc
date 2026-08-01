import json
from pathlib import Path

import pytest

from steamguard_pc import storage
from steamguard_pc.mafile import EncryptedMaFileRequiresPasskey, MaFileDecryptionError, find_mafile_candidates, load_mafile, parse_mafile
from steamguard_pc.models import ImportedSteamGuard


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
DEVICE_ID = "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"
SDA_PASSKEY = "correct horse battery staple"
SDA_SALT = "MTIzNDU2Nzg="
SDA_IV = "MTIzNDU2Nzg5MGFiY2RlZg=="
SDA_CIPHERTEXT = "q4/CnhwdcdRzn7l4L80qTkpyQEAgef8g09baxLG10KMPcav12ZNzruJneluSEKCCHlnyK/ju/J4kvtqeKCSrSc29SFc4pBlOXdJWxxZL8Vi6pm0abP6DlSpGTuHJAbKtVVP2iYCJvx9icvJw7tEnA1EpQiUIPHdn9yEQkU6CAgta3XdpBLl+vR3EfxeG9YGlOGZJzjnVKlfgzRRcRw660RUGT2s+pLMqQFa4ovB/szbqstAHnLKDVaRmnQXUCH6wwZovLYaflUoec+g1GGWOmBGKdANBedpz1xUUqP0SXeaucrYoLVb3LWat/HYEvGyzOiv+Hv8cMhEj0IK75MQ44w=="


def valid_mafile(**overrides):
    raw = {
        "steamid": STEAMID64,
        "account_name": "fixture",
        "shared_secret": SHARED_SECRET,
        "identity_secret": IDENTITY_SECRET,
        "revocation_code": "R12345",
        "Session": {
            "RefreshToken": "refresh-token",
            "AccessToken": "access-token",
            "SteamLoginSecure": "secure-cookie",
            "SessionID": "session-cookie",
        },
    }
    raw.update(overrides)
    return raw

def write_encrypted_sda_fixture(tmp_path) -> Path:
    mafiles_dir = tmp_path / "maFiles"
    mafiles_dir.mkdir()
    mafile_path = mafiles_dir / "account.maFile"
    mafile_path.write_text(SDA_CIPHERTEXT, encoding="utf-8")
    (mafiles_dir / "manifest.json").write_text(
        json.dumps(
            {
                "encrypted": True,
                "entries": [
                    {
                        "filename": "account.maFile",
                        "steamid": 76561197960287930,
                        "encryption_salt": SDA_SALT,
                        "encryption_iv": SDA_IV,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return mafile_path


def test_load_encrypted_sda_mafile_uses_manifest_entry(tmp_path):
    imported = load_mafile(write_encrypted_sda_fixture(tmp_path), passkey=SDA_PASSKEY)

    assert imported.steamid64 == STEAMID64
    assert imported.account_name == "fixture"
    assert imported.shared_secret == SHARED_SECRET
    assert imported.identity_secret == IDENTITY_SECRET
    assert imported.revocation_code == "R12345"
    assert imported.steam_login_secure == "secure-cookie"
    assert imported.sessionid == "session-cookie"


def test_load_encrypted_sda_mafile_requires_passkey(tmp_path):
    with pytest.raises(EncryptedMaFileRequiresPasskey) as excinfo:
        load_mafile(write_encrypted_sda_fixture(tmp_path))

    assert str(excinfo.value) == "encrypted SDA .maFile requires SDA encryption passkey"


def test_load_encrypted_sda_mafile_rejects_wrong_passkey(tmp_path):
    with pytest.raises(MaFileDecryptionError) as excinfo:
        load_mafile(write_encrypted_sda_fixture(tmp_path), passkey="wrong passkey")

    assert str(excinfo.value) == "SDA passkey is incorrect or encrypted .maFile is corrupted"


def test_load_encrypted_sda_mafile_requires_manifest_entry(tmp_path):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(SDA_CIPHERTEXT, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_mafile(mafile_path)

    assert str(excinfo.value) == "encrypted SDA .maFile requires sibling manifest.json"


def test_find_mafile_candidates_discovers_sorted_unique_files(tmp_path):
    root = tmp_path / "maFiles"
    first = root / "b.maFile"
    second = root / "nested" / "A.maFile"
    ignored = root / "not-json.txt"
    second.parent.mkdir(parents=True)
    first.write_text("{}", encoding="utf-8")
    second.write_text("{}", encoding="utf-8")
    ignored.write_text("{}", encoding="utf-8")

    found = find_mafile_candidates([root, first])

    expected = sorted([first.resolve(), second.resolve()], key=lambda path: str(path).casefold())
    assert found == expected


def test_parse_mafile_normalizes_valid_file_with_session_fields():
    imported = parse_mafile(valid_mafile(device_id="android:device"))

    assert imported.steamid64 == STEAMID64
    assert imported.account_name == "fixture"
    assert imported.shared_secret == SHARED_SECRET
    assert imported.identity_secret == IDENTITY_SECRET
    assert imported.revocation_code == "R12345"
    assert imported.device_id == "android:device"
    assert imported.refresh_token == "refresh-token"
    assert imported.access_token == "access-token"
    assert imported.steam_login_secure == "secure-cookie"
    assert imported.sessionid == "session-cookie"


def test_parse_current_sda_session_derives_steam_login_secure():
    imported = parse_mafile(
        valid_mafile(
            Session={
                "SteamID": int(STEAMID64),
                "AccessToken": "access-token",
                "RefreshToken": "refresh-token",
                "SessionID": "session-cookie",
            }
        )
    )

    assert imported.steamid64 == STEAMID64
    assert imported.access_token == "access-token"
    assert imported.refresh_token == "refresh-token"
    assert imported.steam_login_secure == f"{STEAMID64}%7C%7Caccess-token"
    assert imported.sessionid == "session-cookie"

def test_parse_mafile_generates_device_id_when_missing():
    imported = parse_mafile(valid_mafile())

    assert imported.device_id == DEVICE_ID


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}, "missing SteamID64"),
        ({"steamid": "..\\..\\evil", "shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}, "missing SteamID64"),
        ({"steamid": "１２３４５６７８９０１２３４５６", "shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}, "missing SteamID64"),
        ({"steamid": "18446744073709551616", "shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}, "missing SteamID64"),
        ({"steamid": STEAMID64, "identity_secret": IDENTITY_SECRET}, "missing shared_secret"),
        ({"steamid": STEAMID64, "shared_secret": SHARED_SECRET}, "missing identity_secret"),
        ({"steamid": STEAMID64, "shared_secret": "not base64", "identity_secret": IDENTITY_SECRET}, "invalid shared_secret"),
    ],
)
def test_parse_mafile_rejects_invalid_inputs(raw, message):
    with pytest.raises(ValueError, match=f"^{message}$"):
        parse_mafile(raw)


def test_load_accounts_skips_invalid_steamid64_rows(keyring_store):
    config = {
        "version": storage.CONFIG_SCHEMA_VERSION,
        "accounts": [
            {"steamid64": STEAMID64, "account_name": "valid", "device_id": "android:fixture"},
            {"steamid64": "..\\..\\evil", "account_name": "traversal"},
            {"steamid64": "１２３４５６７８９０１２３４５６", "account_name": "non-ascii"},
            {"steamid64": "18446744073709551616", "account_name": "overflow"},
        ],
    }
    storage.config_path().parent.mkdir(parents=True, exist_ok=True)
    storage.config_path().write_text(json.dumps(config), encoding="utf-8")

    accounts = storage.load_accounts()

    assert list(accounts) == [STEAMID64]
    assert accounts[STEAMID64].account_name == "valid"


def test_save_accounts_rejects_invalid_steamid64(keyring_store):
    with pytest.raises(ValueError, match="invalid SteamID64"):
        storage.save_accounts({"bad": storage.AccountMetadata(steamid64="..\\..\\evil")})

    assert not storage.config_path().exists()


def test_upsert_account_rejects_invalid_steamid64(keyring_store):
    with pytest.raises(ValueError, match="invalid SteamID64"):
        storage.upsert_account(storage.AccountMetadata(steamid64="..\\..\\evil"))

    assert not storage.config_path().exists()


def test_put_secret_rejects_invalid_steamid64(keyring_store):
    with pytest.raises(ValueError, match="invalid SteamID64"):
        storage.put_secret("..\\..\\evil", "shared_secret", SHARED_SECRET)

    assert keyring_store == {}


def test_store_imported_guard_rejects_invalid_steamid64_before_writing(keyring_store):
    imported = ImportedSteamGuard(
        account_name="fixture",
        steamid64="..\\..\\evil",
        shared_secret=SHARED_SECRET,
        identity_secret=IDENTITY_SECRET,
    )

    with pytest.raises(ValueError, match="invalid SteamID64"):
        storage.store_imported_guard(imported)

    assert keyring_store == {}
    assert not storage.config_path().exists()

def test_store_imported_guard_keeps_secrets_out_of_config(keyring_store):
    imported = parse_mafile(valid_mafile())
    metadata = storage.store_imported_guard(imported)

    assert metadata.steamid64 == STEAMID64
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:shared_secret")] == SHARED_SECRET
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:identity_secret")] == IDENTITY_SECRET
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] == "secure-cookie"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:sessionid")] == "session-cookie"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:revocation_code")] == "R12345"

    config_text = storage.config_path().read_text(encoding="utf-8")
    config = json.loads(config_text)
    assert config["version"] == storage.CONFIG_SCHEMA_VERSION
    assert config["accounts"][0]["steamid64"] == STEAMID64
    for forbidden in [
        "shared_secret",
        "identity_secret",
        "steamLoginSecure",
        "sessionid",
        SHARED_SECRET,
        IDENTITY_SECRET,
        "secure-cookie",
        "session-cookie",
        "refresh-token",
        "access-token",
        "R12345",
    ]:
        assert forbidden not in config_text


def test_parse_and_store_authenticator_metadata(keyring_store):
    imported = parse_mafile(
        valid_mafile(
            SerialNumber="serial-1",
            TokenGID="token-gid-1",
            uri="otpauth://totp/steam?secret=fixture",
        )
    )

    assert imported.serial_number == "serial-1"
    assert imported.token_gid == "token-gid-1"
    assert imported.uri == "otpauth://totp/steam?secret=fixture"

    storage.store_imported_guard(imported)

    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:serial_number")] == "serial-1"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:token_gid")] == "token-gid-1"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:uri")] == "otpauth://totp/steam?secret=fixture"
    config_text = storage.config_path().read_text(encoding="utf-8")
    for forbidden in [
        "serial_number",
        "token_gid",
        "uri",
        "serial-1",
        "token-gid-1",
        "otpauth://totp/steam?secret=fixture",
    ]:
        assert forbidden not in config_text


def test_delete_account_removes_metadata_and_all_secrets(keyring_store):
    storage.upsert_account(
        storage.AccountMetadata(
            steamid64=STEAMID64,
            account_name="fixture",
            device_id="android:fixture",
            last_imported_at="2026-07-31T00:00:00Z",
        )
    )
    for field in storage.SECRET_FIELDS:
        storage.put_secret(STEAMID64, field, f"secret-{field}")

    deleted = storage.delete_account(STEAMID64)

    assert deleted.account_name == "fixture"
    assert STEAMID64 not in storage.load_accounts()
    assert json.loads(storage.config_path().read_text(encoding="utf-8"))["accounts"] == []
    for field in storage.SECRET_FIELDS:
        assert storage.get_secret(STEAMID64, field) is None


def test_delete_authenticator_secrets_removes_only_authenticator_material(keyring_store):
    storage.upsert_account(
        storage.AccountMetadata(
            steamid64=STEAMID64,
            account_name="fixture",
            device_id="android:fixture",
            last_imported_at="2026-07-31T00:00:00Z",
        )
    )
    for field in storage.SECRET_FIELDS:
        storage.put_secret(STEAMID64, field, f"secret-{field}")

    storage.delete_authenticator_secrets(STEAMID64)

    for field in ("shared_secret", "identity_secret", "revocation_code", "serial_number", "token_gid", "uri"):
        assert storage.get_secret(STEAMID64, field) is None
    for field in ("refresh_token", "access_token", "access_token_obtained_at", "steamLoginSecure", "sessionid"):
        assert storage.get_secret(STEAMID64, field) == f"secret-{field}"
    metadata = storage.load_accounts()[STEAMID64]
    assert metadata.device_id == "android:fixture"


def test_null_keyring_backend_is_rejected(monkeypatch):
    null_backend_type = type("Keyring", (), {"__module__": "keyring.backends.null"})
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: null_backend_type())
    message = "Windows secret storage is unavailable; keyring is using the null backend"

    operations = [
        lambda: storage.put_secret(STEAMID64, "shared_secret", SHARED_SECRET),
        lambda: storage.get_secret(STEAMID64, "shared_secret"),
        lambda: storage.delete_secret(STEAMID64, "shared_secret"),
    ]
    for operation in operations:
        with pytest.raises(storage.SecretStorageUnavailable, match=f"^{message}$"):
            operation()
