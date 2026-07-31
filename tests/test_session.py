import pytest

from steamguard_pc import storage
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
        match=rf"^missing Steam Community cookies for {STEAMID64}; run `steamguard-pc set-cookies {STEAMID64}`$",
    ):
        get_community_session(STEAMID64)
