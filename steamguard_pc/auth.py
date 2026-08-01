import base64
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from requests.cookies import RequestsCookieJar
from urllib.parse import quote

import requests

from ._protobuf import Field, WireType, decode_message, encode_message, encode_nested
from .crypto import login_confirmation_signature


AUTH_SERVICE_URL = "https://api.steampowered.com/IAuthenticationService/{method}/v1/"
MOBILE_USER_AGENT = "okhttp/4.9.2"
MOBILE_COOKIE = "mobileClient=android; mobileClientVersion=777777 3.10.3"
MOBILE_API_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "user-agent": MOBILE_USER_AGENT,
    "cookie": MOBILE_COOKIE,
}
MOBILE_DEVICE_FRIENDLY_NAME = "Galaxy S25"
OSTYPE_ANDROID_UNKNOWN = -500
MOBILE_GAMING_DEVICE_TYPE = 528
PLATFORM_MOBILE_APP = 3
SESSION_PERSISTENT = 1
TOKEN_RENEWAL_NONE = 0
TOKEN_RENEWAL_ALLOW = 1
GUARD_NONE = 1
GUARD_EMAIL_CODE = 2
GUARD_DEVICE_CODE = 3
GUARD_DEVICE_CONFIRMATION = 4
GUARD_EMAIL_CONFIRMATION = 5
GUARD_MACHINE_TOKEN = 6
GUARD_LEGACY_MACHINE_AUTH = 7
SUPPORTED_CODE_GUARDS = {GUARD_EMAIL_CODE, GUARD_DEVICE_CODE}
SUPPORTED_CONFIRMATION_GUARDS = {GUARD_DEVICE_CONFIRMATION, GUARD_EMAIL_CONFIRMATION}
PASSIVE_GUARDS = {GUARD_NONE}
REQUEST_TIMEOUT = 30
LOGIN_FINALIZE_URL = "https://login.steampowered.com/jwt/finalizelogin"
COMMUNITY_HOME_REDIRECT = "https://steamcommunity.com/login/home/?goto="
COMMUNITY_DOMAIN = "steamcommunity.com"
STORE_DOMAIN = "store.steampowered.com"
HELP_DOMAIN = "help.steampowered.com"


GUARD_TYPE_NAMES = {
    GUARD_NONE: "none",
    GUARD_EMAIL_CODE: "email code",
    GUARD_DEVICE_CODE: "mobile authenticator code",
    GUARD_DEVICE_CONFIRMATION: "mobile app confirmation",
    GUARD_EMAIL_CONFIRMATION: "email confirmation",
    GUARD_MACHINE_TOKEN: "machine token",
    GUARD_LEGACY_MACHINE_AUTH: "legacy machine auth",
}

_ALLOWED_CONFIRMATION = {
    1: Field(1, "type", "varint"),
    2: Field(2, "message", "length"),
}
_RSA_RESPONSE = {
    1: Field(1, "publickey_mod", "length"),
    2: Field(2, "publickey_exp", "length"),
    3: Field(3, "timestamp", "varint"),
}
_BEGIN_RESPONSE = {
    1: Field(1, "client_id", "varint"),
    2: Field(2, "request_id", "length"),
    3: Field(3, "interval", "fixed32"),
    4: Field(4, "allowed_confirmations", "length", repeated=True, message=_ALLOWED_CONFIRMATION),
    5: Field(5, "steamid", "varint"),
    6: Field(6, "weak_token", "length"),
    8: Field(8, "extended_error_message", "length"),
}
_POLL_RESPONSE = {
    1: Field(1, "new_client_id", "varint"),
    2: Field(2, "new_challenge_url", "length"),
    3: Field(3, "refresh_token", "length"),
    4: Field(4, "access_token", "length"),
    5: Field(5, "had_remote_interaction", "varint"),
    6: Field(6, "account_name", "length"),
    7: Field(7, "new_guard_data", "length"),
    8: Field(8, "agreement_session_url", "length"),
}
_ACCESS_TOKEN_RESPONSE = {
    1: Field(1, "access_token", "length"),
    2: Field(2, "refresh_token", "length"),
}
_AUTH_SESSIONS_FOR_ACCOUNT_RESPONSE = {
    1: Field(1, "client_ids", "varint", repeated=True),
}
_AUTH_SESSION_INFO_RESPONSE = {
    1: Field(1, "ip", "length"),
    2: Field(2, "geoloc", "length"),
    3: Field(3, "city", "length"),
    4: Field(4, "state", "length"),
    5: Field(5, "country", "length"),
    6: Field(6, "platform_type", "varint"),
    7: Field(7, "device_friendly_name", "length"),
    8: Field(8, "version", "varint"),
    9: Field(9, "login_history", "varint"),
    10: Field(10, "requestor_location_mismatch", "varint"),
    11: Field(11, "high_usage_login", "varint"),
    12: Field(12, "requested_persistence", "varint"),
    13: Field(13, "device_trust", "varint"),
    14: Field(14, "app_type", "varint"),
}


class SteamAuthError(RuntimeError):
    pass


class SteamAuthTransportError(SteamAuthError):
    pass


class SteamAuthResponseError(SteamAuthError):
    pass


class SteamAuthTimeoutError(SteamAuthError):
    pass

class SteamAuthUnsupportedChallengeError(SteamAuthError):
    pass


@dataclass(frozen=True)
class GuardAction:
    type: int
    message: str | None = None

    @property
    def label(self) -> str:
        return GUARD_TYPE_NAMES.get(self.type, f"unknown guard type {self.type}")

def _unsupported_guard_actions(actions: list[GuardAction]) -> list[GuardAction]:
    supported_guards = SUPPORTED_CODE_GUARDS | SUPPORTED_CONFIRMATION_GUARDS | PASSIVE_GUARDS
    return [action for action in actions if action.type not in supported_guards]


@dataclass
class AuthSession:
    client_id: int
    request_id: bytes
    poll_interval: float
    allowed_confirmations: list[GuardAction] = field(default_factory=list)
    steamid64: str | None = None
    weak_token: str | None = None


@dataclass(frozen=True)
class LoginResult:
    steamid64: str
    account_name: str | None
    refresh_token: str
    access_token: str
    steam_login_secure: str
    sessionid: str
    steam_guard_machine_token: str | None = None


@dataclass(frozen=True)
class LoginConfirmation:
    client_id: int
    version: int
    ip: str | None = None
    geoloc: str | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None
    platform_type: int | None = None
    device_friendly_name: str | None = None
    login_history: int | None = None
    location_mismatch: bool = False
    high_usage_login: bool = False
    requested_persistence: int | None = None
    device_trust: int | None = None
    app_type: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class WebLoginResult:
    steamid64: str
    steam_login_secure: str
    sessionid: str
    steam_refresh_secure: str | None = None


def _optional_payload_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    return text or None


def decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
    import json

    data = json.loads(decoded.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("invalid JWT")
    return data


def jwt_subject(token: str) -> str:
    subject = decode_jwt_payload(token).get("sub")
    if not subject:
        raise ValueError("JWT missing subject")
    return str(subject)

def jwt_expiration(token: str) -> int | None:
    expiration = decode_jwt_payload(token).get("exp")
    if expiration is None:
        return None
    try:
        return int(expiration)
    except (TypeError, ValueError):
        return None


def web_login_from_access_token(steamid64: str, access_token: str, sessionid: str | None = None) -> WebLoginResult:
    if not steamid64:
        raise ValueError("steamid64 is required")
    if not access_token:
        raise ValueError("access_token is required")
    sessionid = sessionid or generate_sessionid()
    steam_login_secure = quote(f"{steamid64}||{access_token}", safe="")
    return WebLoginResult(str(steamid64), steam_login_secure, sessionid)


def generate_sessionid() -> str:
    return secrets.token_hex(12)

def _cookie_value(cookies: RequestsCookieJar, name: str, domain: str | None = None) -> str | None:
    if domain is not None:
        for cookie in cookies:
            if cookie.name == name and cookie.domain.lstrip(".") == domain:
                return cookie.value
    for cookie in cookies:
        if cookie.name == name:
            return cookie.value
    return None


def encrypt_password(publickey_mod_hex: str, publickey_exp_hex: str, password: str) -> str:
    modulus = int(publickey_mod_hex, 16)
    exponent = int(publickey_exp_hex, 16)
    key_size = (modulus.bit_length() + 7) // 8
    message = password.encode("utf-8")
    if len(message) > key_size - 11:
        raise ValueError("password is too long for Steam RSA key")

    padding_len = key_size - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        chunk = secrets.token_bytes(padding_len - len(padding))
        padding.extend(byte for byte in chunk if byte != 0)
    encoded = b"\x00\x02" + bytes(padding[:padding_len]) + b"\x00" + message
    cipher = pow(int.from_bytes(encoded, "big"), exponent, modulus)
    return base64.b64encode(cipher.to_bytes(key_size, "big")).decode("ascii")


class SteamAuthClient:
    def __init__(self, http: requests.Session | None = None) -> None:
        self.http = http or requests.Session()

    def finalize_web_login(
        self,
        refresh_token: str,
        steamid64: str | None = None,
        sessionid: str | None = None,
    ) -> WebLoginResult:
        sessionid = sessionid or generate_sessionid()
        try:
            response = self.http.post(
                LOGIN_FINALIZE_URL,
                data={"nonce": refresh_token, "sessionid": sessionid, "redir": COMMUNITY_HOME_REDIRECT},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            raise SteamAuthTransportError("Steam web-login finalization failed") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise SteamAuthTransportError("Steam web-login finalization failed")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SteamAuthResponseError("Steam web-login finalization response is malformed") from exc
        if not isinstance(payload, dict):
            raise SteamAuthResponseError("Steam web-login finalization response is malformed")

        if steamid64 is None:
            steam_id = payload.get("steamID")
            if not steam_id:
                raise SteamAuthResponseError("Steam web-login finalization response is missing steamID")
            steamid64 = str(steam_id)

        for item in payload.get("transfer_info") or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            params = item.get("params")
            if not isinstance(url, str) or not isinstance(params, Mapping):
                continue
            transfer_data = dict(params)
            transfer_data["steamID"] = steamid64
            try:
                transfer_response = self.http.post(url, data=transfer_data, timeout=REQUEST_TIMEOUT)
            except requests.exceptions.RequestException as exc:
                raise SteamAuthTransportError("Steam web-login finalization failed") from exc
            if transfer_response.status_code < 200 or transfer_response.status_code >= 300:
                raise SteamAuthTransportError("Steam web-login finalization failed")

        steam_login_secure = _cookie_value(self.http.cookies, "steamLoginSecure", COMMUNITY_DOMAIN)
        sessionid_cookie = _cookie_value(self.http.cookies, "sessionid", COMMUNITY_DOMAIN)
        if not steam_login_secure or not sessionid_cookie:
            steam_login_secure = steam_login_secure or _cookie_value(self.http.cookies, "steamLoginSecure")
            sessionid_cookie = sessionid_cookie or _cookie_value(self.http.cookies, "sessionid")
        if not steam_login_secure or not sessionid_cookie:
            raise SteamAuthResponseError("Steam web-login finalization did not return Community cookies")

        return WebLoginResult(
            steamid64=steamid64,
            steam_login_secure=steam_login_secure,
            sessionid=sessionid_cookie,
            steam_refresh_secure=_cookie_value(self.http.cookies, "steamRefreshSecure", COMMUNITY_DOMAIN)
            or _cookie_value(self.http.cookies, "steamRefreshSecure"),
        )

    def get_rsa_key(self, account_name: str) -> dict[str, str]:
        request = encode_message([(1, "length", account_name)])
        payload = self._api_request("GetPasswordRSAPublicKey", request, _RSA_RESPONSE, method="GET")
        try:
            return {
                "publickey_mod": str(payload["publickey_mod"]),
                "publickey_exp": str(payload["publickey_exp"]),
                "timestamp": str(payload["timestamp"]),
            }
        except KeyError as exc:
            raise SteamAuthResponseError("Steam RSA response is missing a required field") from exc

    def start_session_with_credentials(
        self,
        account_name: str,
        password: str,
        steam_guard_machine_token: str | None = None,
    ) -> AuthSession:
        rsa_key = self.get_rsa_key(account_name)
        encrypted_password = encrypt_password(rsa_key["publickey_mod"], rsa_key["publickey_exp"], password)
        device_details = encode_nested(
            9,
            [
                (1, "length", MOBILE_DEVICE_FRIENDLY_NAME),
                (2, "varint", PLATFORM_MOBILE_APP),
                (3, "varint", OSTYPE_ANDROID_UNKNOWN),
                (4, "varint", MOBILE_GAMING_DEVICE_TYPE),
            ],
        )
        fields: list[tuple[int, WireType, Any]] = [
            (1, "length", "SteamGuardPC"),
            (2, "length", account_name),
            (3, "length", encrypted_password),
            (4, "varint", int(rsa_key["timestamp"])),
            (5, "varint", True),
            (6, "varint", PLATFORM_MOBILE_APP),
            (7, "varint", SESSION_PERSISTENT),
            (8, "length", "Mobile"),
            device_details,
        ]
        if steam_guard_machine_token:
            fields.append((10, "length", steam_guard_machine_token))

        payload = self._api_request("BeginAuthSessionViaCredentials", encode_message(fields), _BEGIN_RESPONSE)
        if not payload.get("client_id") or not payload.get("request_id"):
            raise SteamAuthResponseError(
                str(payload.get("extended_error_message") or "Steam authentication response is missing session identifiers")
            )
        return AuthSession(
            client_id=int(payload.get("client_id", 0)),
            request_id=_coerce_bytes(payload.get("request_id", b"")),
            poll_interval=float(payload.get("interval", 1.0) or 1.0),
            allowed_confirmations=[
                GuardAction(type=int(item.get("type", 0)), message=item.get("message"))
                for item in payload.get("allowed_confirmations", [])
                if isinstance(item, Mapping)
            ],
            steamid64=str(payload["steamid"]) if payload.get("steamid") else None,
            weak_token=str(payload["weak_token"]) if payload.get("weak_token") else None,
        )

    def submit_steam_guard_code(self, auth_session: AuthSession, code: str, code_type: int) -> None:
        if not auth_session.steamid64:
            raise SteamAuthResponseError("SteamID is unavailable for this login attempt")
        request = encode_message(
            [
                (1, "varint", auth_session.client_id),
                (2, "fixed64", int(auth_session.steamid64)),
                (3, "length", code),
                (4, "varint", code_type),
            ]
        )
        self._api_request("UpdateAuthSessionWithSteamGuardCode", request, {})

    def poll_login_status(self, auth_session: AuthSession) -> dict[str, Any]:
        request = encode_message(
            [
                (1, "varint", auth_session.client_id),
                (2, "length", auth_session.request_id),
            ]
        )
        payload = self._api_request("PollAuthSessionStatus", request, _POLL_RESPONSE)
        if payload.get("new_client_id"):
            auth_session.client_id = int(payload["new_client_id"])
        return payload

    def refresh_access_token(
        self,
        refresh_token: str,
        renew_refresh_token: bool = False,
    ) -> tuple[str, str | None]:
        request = encode_message(
            [
                (1, "length", refresh_token),
                (2, "fixed64", int(jwt_subject(refresh_token))),
                (3, "varint", TOKEN_RENEWAL_ALLOW if renew_refresh_token else TOKEN_RENEWAL_NONE),
            ]
        )
        payload = self._api_request("GenerateAccessTokenForApp", request, _ACCESS_TOKEN_RESPONSE)
        access_token = payload.get("access_token")
        if not access_token:
            raise SteamAuthResponseError("Steam access-token response is missing access_token")
        return str(access_token), str(payload["refresh_token"]) if payload.get("refresh_token") else None

    def get_login_confirmation_client_ids(self, access_token: str) -> list[int]:
        payload = self._api_request(
            "GetAuthSessionsForAccount",
            b"",
            _AUTH_SESSIONS_FOR_ACCOUNT_RESPONSE,
            access_token=access_token,
            method="GET",
        )
        client_ids = payload.get("client_ids") or []
        return [int(client_id) for client_id in client_ids]

    def get_login_confirmation(self, access_token: str, client_id: int) -> LoginConfirmation:
        request = encode_message([(1, "varint", int(client_id))])
        payload = self._api_request(
            "GetAuthSessionInfo",
            request,
            _AUTH_SESSION_INFO_RESPONSE,
            access_token=access_token,
        )
        if "version" not in payload:
            raise SteamAuthResponseError("Steam login-confirmation response is missing version")

        return LoginConfirmation(
            client_id=int(client_id),
            version=int(payload["version"]),
            ip=_optional_payload_text(payload, "ip"),
            geoloc=_optional_payload_text(payload, "geoloc"),
            city=_optional_payload_text(payload, "city"),
            state=_optional_payload_text(payload, "state"),
            country=_optional_payload_text(payload, "country"),
            platform_type=int(payload["platform_type"]) if "platform_type" in payload else None,
            device_friendly_name=_optional_payload_text(payload, "device_friendly_name"),
            login_history=int(payload["login_history"]) if "login_history" in payload else None,
            location_mismatch=bool(payload.get("requestor_location_mismatch", payload.get("location_mismatch", False))),
            high_usage_login=bool(payload.get("high_usage_login", False)),
            requested_persistence=int(payload["requested_persistence"]) if "requested_persistence" in payload else None,
            device_trust=int(payload["device_trust"]) if "device_trust" in payload else None,
            app_type=int(payload["app_type"]) if "app_type" in payload else None,
            raw=dict(payload),
        )

    def get_login_confirmations(self, access_token: str) -> list[LoginConfirmation]:
        return [
            self.get_login_confirmation(access_token, client_id)
            for client_id in self.get_login_confirmation_client_ids(access_token)
        ]

    def respond_to_login_confirmation(
        self,
        access_token: str,
        steamid64: str,
        shared_secret_b64: str,
        confirmation: LoginConfirmation,
        *,
        confirm: bool,
        persistence: int = SESSION_PERSISTENT,
    ) -> None:
        signature = login_confirmation_signature(
            shared_secret_b64,
            confirmation.version,
            confirmation.client_id,
            steamid64,
        )
        request = encode_message(
            [
                (1, "varint", confirmation.version),
                (2, "varint", confirmation.client_id),
                (3, "fixed64", int(steamid64)),
                (4, "length", signature),
                (5, "varint", confirm),
                (6, "varint", persistence),
            ]
        )
        self._api_request(
            "UpdateAuthSessionWithMobileConfirmation",
            request,
            {},
            access_token=access_token,
        )

    def login_with_credentials(
        self,
        account_name: str,
        password: str,
        code_provider: Callable[[GuardAction, AuthSession], str | None],
        confirmation_provider: Callable[[list[GuardAction]], None],
        steam_guard_machine_token: str | None = None,
        timeout_seconds: int = 180,
        sleep: Callable[[float], None] = time.sleep,
    ) -> LoginResult:
        auth_session = self.start_session_with_credentials(account_name, password, steam_guard_machine_token)
        code_actions = [
            action
            for action in auth_session.allowed_confirmations
            if action.type in SUPPORTED_CODE_GUARDS
        ]
        confirmation_actions = [
            action
            for action in auth_session.allowed_confirmations
            if action.type in SUPPORTED_CONFIRMATION_GUARDS
        ]

        if not code_actions and not confirmation_actions:
            unsupported = _unsupported_guard_actions(auth_session.allowed_confirmations)
            if unsupported:
                raise SteamAuthUnsupportedChallengeError(
                    "Steam login requires unsupported guard action(s): "
                    + ", ".join(action.label for action in unsupported)
                )

        if code_actions:
            action = code_actions[0]
            code = code_provider(action, auth_session)
            if not code:
                raise SteamAuthError(f"missing {action.label}")
            self.submit_steam_guard_code(auth_session, code, action.type)
        elif confirmation_actions:
            confirmation_provider(confirmation_actions)

        deadline = time.monotonic() + timeout_seconds
        last_payload: dict[str, Any] = {}
        while time.monotonic() < deadline:
            payload = self.poll_login_status(auth_session)
            last_payload = payload
            refresh_token = payload.get("refresh_token")
            if refresh_token:
                access_token = payload.get("access_token")
                if not access_token:
                    access_token, _ = self.refresh_access_token(str(refresh_token))
                steamid64 = auth_session.steamid64 or jwt_subject(str(refresh_token))
                web_login = web_login_from_access_token(steamid64, str(access_token))
                return LoginResult(
                    steamid64=steamid64,
                    account_name=str(payload["account_name"]) if payload.get("account_name") else account_name,
                    refresh_token=str(refresh_token),
                    access_token=str(access_token),
                    steam_login_secure=web_login.steam_login_secure,
                    sessionid=web_login.sessionid,
                    steam_guard_machine_token=(
                        str(payload["new_guard_data"]) if payload.get("new_guard_data") else None
                    ),
                )
            if payload.get("agreement_session_url"):
                raise SteamAuthUnsupportedChallengeError(
                    "Steam login requires completing an additional Steam agreement or risk challenge"
                )
            if payload.get("new_challenge_url"):
                raise SteamAuthUnsupportedChallengeError(
                    "Steam login requires an unsupported additional Steam authentication challenge"
                )
            sleep(max(0.5, min(auth_session.poll_interval, 5.0)))

        detail = last_payload.get("agreement_session_url") or "timed out waiting for Steam authentication"
        raise SteamAuthTimeoutError(str(detail))

    def _api_request(
        self,
        api_method: str,
        request_data: bytes,
        response_descriptor: Mapping[int, Field],
        method: str = "POST",
        access_token: str | None = None,
    ) -> dict[str, Any]:
        encoded = base64.b64encode(request_data).decode("ascii") if request_data else None
        url = AUTH_SERVICE_URL.format(method=api_method)
        params: dict[str, str] = {}
        if access_token:
            params["access_token"] = access_token
        if method == "GET" and encoded:
            params["input_protobuf_encoded"] = encoded

        if method == "GET" and "mobileClientVersion=" in MOBILE_COOKIE:
            params["origin"] = "SteamMobile"

        headers = dict(MOBILE_API_HEADERS)
        try:
            if method == "GET":
                response = self.http.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                files = {"input_protobuf_encoded": (None, encoded)} if encoded else None
                response = self.http.post(url, params=params, files=files, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise SteamAuthTransportError("Steam authentication request failed") from exc

        if response.status_code < 200 or response.status_code >= 300:
            raise SteamAuthTransportError(f"Steam authentication HTTP {response.status_code}")

        eresult = response.headers.get("x-eresult")
        if eresult and eresult != "1":
            message = response.headers.get("x-error_message") or f"Steam authentication failed ({eresult})"
            raise SteamAuthResponseError(message)

        json_payload = _response_json(response)
        if json_payload is not None:
            payload = json_payload.get("response", json_payload)
            if isinstance(payload, dict):
                return payload
            raise SteamAuthResponseError("Steam authentication JSON response is malformed")

        if not response.content:
            return {}
        try:
            return decode_message(response.content, response_descriptor)
        except ValueError as exc:
            raise SteamAuthResponseError("Steam authentication protobuf response is malformed") from exc


def _response_json(response: requests.Response) -> dict[str, Any] | None:
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.casefold():
        return None
    try:
        payload = response.json()
    except ValueError as exc:
        raise SteamAuthResponseError("Steam authentication JSON response is malformed") from exc
    if not isinstance(payload, dict):
        raise SteamAuthResponseError("Steam authentication JSON response is malformed")
    return payload


def _coerce_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise TypeError("expected bytes-like value")
