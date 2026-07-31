import requests

from . import storage


COOKIE_DOMAIN = "steamcommunity.com"


class SessionExpiredError(RuntimeError):
    pass


def save_community_cookies(steamid64: str, steam_login_secure: str, sessionid: str) -> None:
    if not isinstance(steam_login_secure, str) or not steam_login_secure:
        raise ValueError("steamLoginSecure is required")
    if not isinstance(sessionid, str) or not sessionid:
        raise ValueError("sessionid is required")

    storage.put_secret(steamid64, "steamLoginSecure", steam_login_secure)
    storage.put_secret(steamid64, "sessionid", sessionid)


def get_community_session(steamid64: str) -> requests.Session:
    steam_login_secure = storage.get_secret(steamid64, "steamLoginSecure")
    sessionid = storage.get_secret(steamid64, "sessionid")
    if not steam_login_secure or not sessionid:
        raise SessionExpiredError(
            f"missing Steam Community cookies for {steamid64}; run `steamguard-pc set-cookies {steamid64}`"
        )

    session = requests.Session()
    session.headers.update({"User-Agent": "SteamGuardPC/0.1 requests"})
    for domain in (COOKIE_DOMAIN, f".{COOKIE_DOMAIN}"):
        session.cookies.set("steamLoginSecure", steam_login_secure, domain=domain, path="/")
        session.cookies.set("sessionid", sessionid, domain=domain, path="/")
    return session
