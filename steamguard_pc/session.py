import time

import requests

from . import auth, storage


COOKIE_DOMAIN = "steamcommunity.com"
TOKEN_REFRESH_SKEW_SECONDS = 10 * 60
ACCESS_TOKEN_REFRESH_AGE_SECONDS = 10 * 60
ACCESS_TOKEN_OBTAINED_AT_FIELD = "access_token_obtained_at"


class SessionExpiredError(RuntimeError):
    pass


def save_community_cookies(steamid64: str, steam_login_secure: str, sessionid: str) -> None:
    if not isinstance(steam_login_secure, str) or not steam_login_secure:
        raise ValueError("steamLoginSecure is required")
    if not isinstance(sessionid, str) or not sessionid:
        raise ValueError("sessionid is required")

    storage.put_secret(steamid64, "steamLoginSecure", steam_login_secure)
    storage.put_secret(steamid64, "sessionid", sessionid)


def save_access_token(steamid64: str, access_token: str, now: int | None = None) -> None:
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("access_token is required")
    obtained_at = int(now if now is not None else time.time())
    storage.put_secret(steamid64, "access_token", access_token)
    storage.put_secret(steamid64, ACCESS_TOKEN_OBTAINED_AT_FIELD, str(obtained_at))


def _jwt_expires_within(token: str | None, now: int, skew_seconds: int = TOKEN_REFRESH_SKEW_SECONDS) -> bool:
    if not token:
        return False
    try:
        expiration = auth.jwt_expiration(token)
    except ValueError:
        return False
    return expiration is not None and expiration <= now + skew_seconds


def _access_token_needs_refresh(access_token: str | None, obtained_at: str | None, now: int) -> bool:
    if not access_token:
        return True
    if _jwt_expires_within(access_token, now):
        return True
    try:
        token_age = now - int(obtained_at)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return True
    return token_age >= ACCESS_TOKEN_REFRESH_AGE_SECONDS

def refresh_auth_tokens(
    steamid64: str,
    auth_client: auth.SteamAuthClient | None = None,
    renew_refresh_token: bool = False,
    now: int | None = None,
) -> tuple[str, str]:
    refresh_token = storage.get_secret(steamid64, "refresh_token")
    if not refresh_token:
        raise SessionExpiredError(f"missing Steam refresh token for {steamid64}; run `steamguard-pc login`")

    client = auth_client or auth.SteamAuthClient()
    try:
        if renew_refresh_token:
            access_token, renewed_refresh_token = client.refresh_access_token(refresh_token, renew_refresh_token=True)
        else:
            access_token, renewed_refresh_token = client.refresh_access_token(refresh_token)
    except auth.SteamAuthError as exc:
        raise SessionExpiredError("Steam token refresh failed; run `steamguard-pc login`") from exc

    save_access_token(steamid64, access_token, now=now)
    effective_refresh_token = renewed_refresh_token or refresh_token
    if renewed_refresh_token:
        storage.put_secret(steamid64, "refresh_token", renewed_refresh_token)
    return access_token, effective_refresh_token


def refresh_community_session(
    steamid64: str,
    auth_client: auth.SteamAuthClient | None = None,
    renew_refresh_token: bool = False,
    now: int | None = None,
) -> requests.Session:
    client = auth_client or auth.SteamAuthClient()
    access_token, _ = refresh_auth_tokens(
        steamid64,
        auth_client=client,
        renew_refresh_token=renew_refresh_token,
        now=now,
    )
    web_login = auth.web_login_from_access_token(steamid64, access_token)

    save_community_cookies(steamid64, web_login.steam_login_secure, web_login.sessionid)
    return get_community_session(steamid64, refresh_if_missing=False)


def get_community_session(
    steamid64: str,
    refresh_if_missing: bool = True,
    now: int | None = None,
) -> requests.Session:
    steam_login_secure = storage.get_secret(steamid64, "steamLoginSecure")
    sessionid = storage.get_secret(steamid64, "sessionid")
    if not steam_login_secure or not sessionid:
        if refresh_if_missing:
            try:
                return refresh_community_session(steamid64, now=now)
            except SessionExpiredError as exc:
                if not str(exc).startswith("missing Steam refresh token"):
                    raise
                raise SessionExpiredError(
                    f"missing Steam Community cookies for {steamid64}; run `steamguard-pc login` or `steamguard-pc set-cookies {steamid64}`"
                ) from exc
        raise SessionExpiredError(
            f"missing Steam Community cookies for {steamid64}; run `steamguard-pc login` or `steamguard-pc set-cookies {steamid64}`"
        )

    if refresh_if_missing:
        access_token = storage.get_secret(steamid64, "access_token")
        access_token_obtained_at = storage.get_secret(steamid64, ACCESS_TOKEN_OBTAINED_AT_FIELD)
        refresh_token = storage.get_secret(steamid64, "refresh_token")
        if refresh_token:
            current_time = int(now if now is not None else time.time())
            renew_refresh = _jwt_expires_within(refresh_token, current_time)
            if _access_token_needs_refresh(access_token, access_token_obtained_at, current_time) or renew_refresh:
                return refresh_community_session(steamid64, renew_refresh_token=renew_refresh, now=current_time)

    session = requests.Session()
    session.headers.update({"User-Agent": "SteamGuardPC/0.1 requests"})
    for domain in (COOKIE_DOMAIN, f".{COOKIE_DOMAIN}"):
        session.cookies.set("steamLoginSecure", steam_login_secure, domain=domain, path="/")
        session.cookies.set("sessionid", sessionid, domain=domain, path="/")
    return session
