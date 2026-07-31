from urllib.parse import quote

import pytest

from steamguard_pc import auth
from steamguard_pc._protobuf import Field, decode_message, encode_message, encode_nested


STEAMID64 = "76561197960287930"


def test_protobuf_helpers_round_trip_nested_fields():
    nested = {1: Field(1, "type", "varint"), 2: Field(2, "message", "length")}
    descriptor = {
        1: Field(1, "name", "length"),
        2: Field(2, "count", "varint"),
        3: Field(3, "items", "length", repeated=True, message=nested),
    }

    encoded = encode_message(
        [
            (1, "length", "fixture"),
            (2, "varint", 7),
            encode_nested(3, [(1, "varint", 2), (2, "length", "email")]),
            encode_nested(3, [(1, "varint", 3), (2, "length", "device")]),
        ]
    )

    assert decode_message(encoded, descriptor) == {
        "name": "fixture",
        "count": 7,
        "items": [
            {"type": 2, "message": "email"},
            {"type": 3, "message": "device"},
        ],
    }


def test_encrypt_password_returns_base64_ciphertext():
    modulus = (2**1024 - 109).to_bytes(128, "big").hex()
    encrypted = auth.encrypt_password(modulus, "10001", "password")

    import base64

    assert len(base64.b64decode(encrypted)) == 128


def test_login_with_credentials_submits_guard_code_and_synthesizes_cookies(monkeypatch):
    client = auth.SteamAuthClient()
    calls = []

    monkeypatch.setattr(auth, "encrypt_password", lambda public_mod, public_exp, password: "encrypted-password")

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        calls.append((api_method, request_data, method, access_token))
        if api_method == "GetPasswordRSAPublicKey":
            return {"publickey_mod": "ff", "publickey_exp": "010001", "timestamp": 123}
        if api_method == "BeginAuthSessionViaCredentials":
            return {
                "client_id": 55,
                "request_id": b"request",
                "interval": 0.01,
                "allowed_confirmations": [{"type": auth.GUARD_DEVICE_CODE, "message": "mobile"}],
                "steamid": int(STEAMID64),
            }
        if api_method == "UpdateAuthSessionWithSteamGuardCode":
            return {}
        if api_method == "PollAuthSessionStatus":
            return {
                "refresh_token": "refresh-token",
                "access_token": "access-token",
                "account_name": "fixture",
            }
        raise AssertionError(api_method)

    monkeypatch.setattr(client, "_api_request", fake_api)

    result = client.login_with_credentials(
        "fixture",
        "password",
        code_provider=lambda action, auth_session: "ABCDE",
        confirmation_provider=lambda actions: None,
        sleep=lambda seconds: None,
    )

    assert result.steamid64 == STEAMID64
    assert result.account_name == "fixture"
    assert result.refresh_token == "refresh-token"
    assert result.access_token == "access-token"
    assert result.steam_login_secure == quote(f"{STEAMID64}||access-token", safe="")
    assert result.sessionid
    assert [call[0] for call in calls] == [
        "GetPasswordRSAPublicKey",
        "BeginAuthSessionViaCredentials",
        "UpdateAuthSessionWithSteamGuardCode",
        "PollAuthSessionStatus",
    ]


def test_refresh_access_token_uses_refresh_token_subject(monkeypatch):
    client = auth.SteamAuthClient()
    token = "header.eyJzdWIiOiAiNzY1NjExOTc5NjAyODc5MzAifQ.signature"
    captured = {}

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        captured["method"] = api_method
        captured["request"] = request_data
        return {"access_token": "access-token"}

    monkeypatch.setattr(client, "_api_request", fake_api)

    assert client.refresh_access_token(token) == ("access-token", None)
    assert captured["method"] == "GenerateAccessTokenForApp"
