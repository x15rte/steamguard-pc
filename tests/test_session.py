import base64
import json
import pytest

from steamguard_pc import auth, storage, session as session_module
from steamguard_pc.session import SessionExpiredError, get_community_session, save_community_cookies


STEAMID64 = "76561197960287930"

def jwt_token(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


def test_save_community_cookies_stores_cookie_secrets(keyring_store):
    save_community_cookies(STEAMID64, "secure-cookie", "session-cookie")

    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] == "secure-cookie"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:sessionid")] == "session-cookie"


def test_get_community_session_sets_cookie_domains(keyring_store):
    save_community_cookies(STEAMID64, "secure-cookie", "session-cookie")

    session = get_community_session(STEAMID64)

    assert session.headers["User-Agent"] == "SteamGuardPC/0.1 requests"
    cookies = {(cookie.name, cookie.domain): cookie.value for cookie in session.cookies}
    assert cookies[("steamLoginSecure", "steamcommunity.com")] == "secure-cookie"
    assert cookies[("sessionid", "steamcommunity.com")] == "session-cookie"
    assert cookies[("steamLoginSecure", ".steamcommunity.com")] == "secure-cookie"
    assert cookies[("sessionid", ".steamcommunity.com")] == "session-cookie"


def test_get_community_session_raises_when_cookie_missing(keyring_store):
    keyring_store[(storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] = "secure-cookie"

    with pytest.raises(
        SessionExpiredError,
        match=rf"^missing Steam Community cookies for {STEAMID64}; run `steamguard-pc login` or `steamguard-pc set-cookies {STEAMID64}`$",
    ):
        get_community_session(STEAMID64, refresh_if_missing=False)


def test_get_community_session_refreshes_from_refresh_token_when_cookies_missing(monkeypatch, keyring_store):
    storage.put_secret(STEAMID64, "refresh_token", "refresh-token")

    class FakeAuthClient:
        def refresh_access_token(self, refresh_token):
            assert refresh_token == "refresh-token"
            return "access-token", None

        def finalize_web_login(self, refresh_token, steamid64):
            assert refresh_token == "refresh-token"
            assert steamid64 == STEAMID64
            return auth.WebLoginResult(steamid64, "secure-cookie", "session-cookie")

    monkeypatch.setattr(session_module.auth, "SteamAuthClient", FakeAuthClient)

    community_session = get_community_session(STEAMID64)

    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:access_token")] == "access-token"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] == "secure-cookie"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:sessionid")] == "session-cookie"
    cookies = {(cookie.name, cookie.domain): cookie.value for cookie in community_session.cookies}
    assert cookies[("steamLoginSecure", "steamcommunity.com")] == "secure-cookie"
    assert cookies[("sessionid", "steamcommunity.com")] == "session-cookie"
    assert cookies[("steamLoginSecure", ".steamcommunity.com")] == "secure-cookie"
    assert cookies[("sessionid", ".steamcommunity.com")] == "session-cookie"


def test_refresh_auth_tokens_stores_renewed_tokens(keyring_store):
    storage.put_secret(STEAMID64, "refresh_token", "refresh-token")

    class FakeAuthClient:
        def refresh_access_token(self, refresh_token):
            assert refresh_token == "refresh-token"
            return "access-token", "new-refresh-token"

    tokens = session_module.refresh_auth_tokens(STEAMID64, FakeAuthClient())

    assert tokens == ("access-token", "new-refresh-token")
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:access_token")] == "access-token"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:refresh_token")] == "new-refresh-token"


def test_get_community_session_refreshes_before_access_token_expiry(monkeypatch, keyring_store):
    save_community_cookies(STEAMID64, "secure-cookie", "session-cookie")
    storage.put_secret(STEAMID64, "refresh_token", jwt_token({"sub": STEAMID64, "exp": 1700010000}))
    storage.put_secret(STEAMID64, "access_token", jwt_token({"sub": STEAMID64, "exp": 1700000050}))

    class FakeAuthClient:
        def refresh_access_token(self, refresh_token):
            return "new-access-token", None

        def finalize_web_login(self, refresh_token, steamid64):
            assert steamid64 == STEAMID64
            return auth.WebLoginResult(STEAMID64, "fresh-secure", "fresh-session")

    monkeypatch.setattr(session_module.auth, "SteamAuthClient", FakeAuthClient)

    community_session = get_community_session(STEAMID64, now=1700000000)

    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:access_token")] == "new-access-token"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] == "fresh-secure"
    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:sessionid")] == "fresh-session"
    cookies = {(cookie.name, cookie.domain): cookie.value for cookie in community_session.cookies}
    assert cookies[("steamLoginSecure", "steamcommunity.com")] == "fresh-secure"
    assert cookies[("sessionid", "steamcommunity.com")] == "fresh-session"


def test_get_community_session_renews_refresh_token_when_refresh_token_near_expiry(monkeypatch, keyring_store):
    save_community_cookies(STEAMID64, "secure-cookie", "session-cookie")
    storage.put_secret(STEAMID64, "access_token", jwt_token({"sub": STEAMID64, "exp": 1700010000}))
    storage.put_secret(STEAMID64, "refresh_token", jwt_token({"sub": STEAMID64, "exp": 1700000050}))

    class FakeAuthClient:
        def refresh_access_token(self, refresh_token, renew_refresh_token=False):
            assert renew_refresh_token is True
            return "new-access-token", "new-refresh-token"

        def finalize_web_login(self, refresh_token, steamid64):
            assert refresh_token == "new-refresh-token"
            assert steamid64 == STEAMID64
            return auth.WebLoginResult(STEAMID64, "fresh-secure", "fresh-session")

    monkeypatch.setattr(session_module.auth, "SteamAuthClient", FakeAuthClient)

    get_community_session(STEAMID64, now=1700000000)

    assert keyring_store[(storage.SERVICE, f"{STEAMID64}:refresh_token")] == "new-refresh-token"


def test_get_community_session_keeps_valid_cookies_when_token_expiry_unknown(monkeypatch, keyring_store):
    save_community_cookies(STEAMID64, "secure-cookie", "session-cookie")
    storage.put_secret(STEAMID64, "access_token", "opaque-access-token")
    storage.put_secret(STEAMID64, "refresh_token", "opaque-refresh-token")

    class FakeAuthClient:
        def __init__(self):
            raise AssertionError("unexpected auth client")

    monkeypatch.setattr(session_module.auth, "SteamAuthClient", FakeAuthClient)

    community_session = get_community_session(STEAMID64, now=1700000000)

    cookies = {(cookie.name, cookie.domain): cookie.value for cookie in community_session.cookies}
    assert cookies[("steamLoginSecure", "steamcommunity.com")] == "secure-cookie"
    assert cookies[("sessionid", "steamcommunity.com")] == "session-cookie"
