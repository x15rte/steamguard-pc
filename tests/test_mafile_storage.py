import json

import pytest

from steamguard_pc import storage
from steamguard_pc.mafile import find_mafile_candidates, parse_mafile


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
DEVICE_ID = "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"


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


def test_parse_mafile_generates_device_id_when_missing():
    imported = parse_mafile(valid_mafile())

    assert imported.device_id == DEVICE_ID


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}, "missing SteamID64"),
        ({"steamid": STEAMID64, "identity_secret": IDENTITY_SECRET}, "missing shared_secret"),
        ({"steamid": STEAMID64, "shared_secret": SHARED_SECRET}, "missing identity_secret"),
        ({"steamid": STEAMID64, "shared_secret": "not base64", "identity_secret": IDENTITY_SECRET}, "invalid shared_secret"),
    ],
)
def test_parse_mafile_rejects_invalid_inputs(raw, message):
    with pytest.raises(ValueError, match=f"^{message}$"):
        parse_mafile(raw)


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
