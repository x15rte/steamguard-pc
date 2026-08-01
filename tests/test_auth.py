import base64
import json
from urllib.parse import parse_qs

import pytest

from steamguard_pc import auth
from steamguard_pc._protobuf import Field, decode_message, encode_message, encode_nested


STEAMID64 = "76561197960287930"
ACCESS_TOKEN_COOKIE = f"{STEAMID64}%7C%7Caccess-token"

def jwt_token(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


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


def test_api_request_uses_mobile_headers_and_origin(requests_mock):
    client = auth.SteamAuthClient()
    url = auth.AUTH_SERVICE_URL.format(method="GetPasswordRSAPublicKey")
    requests_mock.get(url, json={"response": {}}, headers={"content-type": "application/json"})
    request_data = encode_message([(1, "length", "fixture")])

    client._api_request("GetPasswordRSAPublicKey", request_data, {}, method="GET")

    request = requests_mock.last_request
    assert f"input_protobuf_encoded={base64.b64encode(request_data).decode('ascii')}" in request.url
    assert "origin=SteamMobile" in request.url
    assert request.headers["user-agent"] == auth.MOBILE_USER_AGENT
    assert request.headers["cookie"] == auth.MOBILE_COOKIE
    assert request.headers["sec-fetch-site"] == "cross-site"
    assert request.headers["sec-fetch-mode"] == "cors"
    assert request.headers["sec-fetch-dest"] == "empty"


def test_login_with_credentials_uses_mobile_access_token_cookie(monkeypatch):
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

    monkeypatch.setattr(auth, "generate_sessionid", lambda: "community-session")
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
    assert result.steam_login_secure == ACCESS_TOKEN_COOKIE
    assert result.sessionid == "community-session"
    assert [call[0] for call in calls] == [
        "GetPasswordRSAPublicKey",
        "BeginAuthSessionViaCredentials",
        "UpdateAuthSessionWithSteamGuardCode",
        "PollAuthSessionStatus",
    ]

def test_login_with_credentials_rejects_unsupported_guard_without_polling(monkeypatch):
    client = auth.SteamAuthClient()
    calls = []

    monkeypatch.setattr(auth, "encrypt_password", lambda public_mod, public_exp, password: "encrypted-password")

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        calls.append(api_method)
        if api_method == "GetPasswordRSAPublicKey":
            return {"publickey_mod": "ff", "publickey_exp": "010001", "timestamp": 123}
        if api_method == "BeginAuthSessionViaCredentials":
            return {
                "client_id": 55,
                "request_id": b"request",
                "interval": 0.01,
                "allowed_confirmations": [{"type": auth.GUARD_MACHINE_TOKEN, "message": "machine"}],
                "steamid": int(STEAMID64),
            }
        if api_method == "PollAuthSessionStatus":
            raise AssertionError("unexpected polling")
        raise AssertionError(api_method)

    monkeypatch.setattr(client, "_api_request", fake_api)

    with pytest.raises(auth.SteamAuthUnsupportedChallengeError) as excinfo:
        client.login_with_credentials(
            "fixture",
            "password",
            code_provider=lambda action, auth_session: None,
            confirmation_provider=lambda actions: None,
            sleep=lambda seconds: None,
        )

    assert str(excinfo.value) == "Steam login requires unsupported guard action(s): machine token"
    assert "PollAuthSessionStatus" not in calls


def test_login_with_credentials_uses_supported_guard_when_unsupported_also_offered(monkeypatch):
    client = auth.SteamAuthClient()
    calls = []

    monkeypatch.setattr(auth, "encrypt_password", lambda public_mod, public_exp, password: "encrypted-password")

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        calls.append(api_method)
        if api_method == "GetPasswordRSAPublicKey":
            return {"publickey_mod": "ff", "publickey_exp": "010001", "timestamp": 123}
        if api_method == "BeginAuthSessionViaCredentials":
            return {
                "client_id": 55,
                "request_id": b"request",
                "interval": 0.01,
                "allowed_confirmations": [
                    {"type": auth.GUARD_MACHINE_TOKEN, "message": "machine"},
                    {"type": auth.GUARD_DEVICE_CODE, "message": "mobile"},
                ],
                "steamid": int(STEAMID64),
            }
        if api_method == "UpdateAuthSessionWithSteamGuardCode":
            return {}
        if api_method == "PollAuthSessionStatus":
            return {"refresh_token": "refresh-token", "access_token": "access-token"}
        raise AssertionError(api_method)

    def fake_finalize(refresh_token, steamid64, sessionid=None):
        return auth.WebLoginResult(steamid64, "community-secure", "community-session")

    monkeypatch.setattr(client, "_api_request", fake_api)
    monkeypatch.setattr(client, "finalize_web_login", fake_finalize)

    result = client.login_with_credentials(
        "fixture",
        "password",
        code_provider=lambda action, auth_session: "ABCDE",
        confirmation_provider=lambda actions: None,
        sleep=lambda seconds: None,
    )

    assert result.access_token == "access-token"
    assert "UpdateAuthSessionWithSteamGuardCode" in calls
    assert "PollAuthSessionStatus" in calls


def test_login_with_credentials_rejects_agreement_url_from_poll(monkeypatch):
    client = auth.SteamAuthClient()

    monkeypatch.setattr(auth, "encrypt_password", lambda public_mod, public_exp, password: "encrypted-password")

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        if api_method == "GetPasswordRSAPublicKey":
            return {"publickey_mod": "ff", "publickey_exp": "010001", "timestamp": 123}
        if api_method == "BeginAuthSessionViaCredentials":
            return {
                "client_id": 55,
                "request_id": b"request",
                "interval": 0.01,
                "allowed_confirmations": [],
                "steamid": int(STEAMID64),
            }
        if api_method == "PollAuthSessionStatus":
            return {"agreement_session_url": "https://steamcommunity.com/agreements"}
        raise AssertionError(api_method)

    monkeypatch.setattr(client, "_api_request", fake_api)

    with pytest.raises(auth.SteamAuthUnsupportedChallengeError) as excinfo:
        client.login_with_credentials(
            "fixture",
            "password",
            code_provider=lambda action, auth_session: None,
            confirmation_provider=lambda actions: None,
            sleep=lambda seconds: None,
        )

    assert str(excinfo.value) == "Steam login requires completing an additional Steam agreement or risk challenge"


def test_start_session_with_credentials_rejects_missing_session_identifiers(monkeypatch):
    client = auth.SteamAuthClient()

    monkeypatch.setattr(auth, "encrypt_password", lambda public_mod, public_exp, password: "encrypted-password")

    def fake_api(api_method, request_data, response_descriptor, method="POST", access_token=None):
        if api_method == "GetPasswordRSAPublicKey":
            return {"publickey_mod": "ff", "publickey_exp": "010001", "timestamp": 123}
        if api_method == "BeginAuthSessionViaCredentials":
            return {"extended_error_message": "captcha required"}
        raise AssertionError(api_method)

    monkeypatch.setattr(client, "_api_request", fake_api)

    with pytest.raises(auth.SteamAuthResponseError) as excinfo:
        client.start_session_with_credentials("fixture", "password")

    assert str(excinfo.value) == "captcha required"


def test_finalize_web_login_posts_nonce_follows_transfers_and_reads_community_cookies(requests_mock):
    client = auth.SteamAuthClient()
    transfer_url = "https://steamcommunity.com/login/transfer"
    requests_mock.post(
        auth.LOGIN_FINALIZE_URL,
        json={
            "steamID": STEAMID64,
            "transfer_info": [
                {"url": transfer_url, "params": {"nonce": "transfer-nonce", "auth": "transfer-auth"}}
            ],
        },
    )

    def transfer_callback(request, context):
        client.http.cookies.set("steamLoginSecure", "community-secure", domain="steamcommunity.com", path="/")
        client.http.cookies.set("sessionid", "community-session", domain="steamcommunity.com", path="/")
        client.http.cookies.set("steamRefreshSecure", "refresh-secure", domain="steamcommunity.com", path="/")
        return "ok"

    requests_mock.post(transfer_url, text=transfer_callback)

    result = client.finalize_web_login("refresh-token", sessionid="generated-session")

    assert result == auth.WebLoginResult(STEAMID64, "community-secure", "community-session", "refresh-secure")
    assert len(requests_mock.request_history) == 2
    finalize_request = requests_mock.request_history[0]
    assert finalize_request.url == auth.LOGIN_FINALIZE_URL
    assert parse_qs(finalize_request.text) == {
        "nonce": ["refresh-token"],
        "sessionid": ["generated-session"],
        "redir": [auth.COMMUNITY_HOME_REDIRECT],
    }
    transfer_request = requests_mock.request_history[1]
    assert transfer_request.url == transfer_url
    assert parse_qs(transfer_request.text) == {
        "nonce": ["transfer-nonce"],
        "auth": ["transfer-auth"],
        "steamID": [STEAMID64],
    }


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


def test_jwt_expiration_reads_exp_claim():
    token = jwt_token({"sub": STEAMID64, "exp": 1700000050})

    assert auth.jwt_expiration(token) == 1700000050


def test_jwt_expiration_returns_none_when_missing():
    token = jwt_token({"sub": STEAMID64})

    assert auth.jwt_expiration(token) is None
