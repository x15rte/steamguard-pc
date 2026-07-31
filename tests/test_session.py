import pytest

from steamguard_pc import auth, storage, session as session_module
from steamguard_pc.session import SessionExpiredError, get_community_session, save_community_cookies


STEAMID64 = "76561197960287930"


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
