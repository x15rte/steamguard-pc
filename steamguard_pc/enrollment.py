from dataclasses import dataclass
from typing import Any

import requests

from .crypto import generate_device_id, steam_totp, validate_base64_secret
from .models import ImportedSteamGuard


STEAM_API_BASE = "https://api.steampowered.com"
QUERY_TIME_URL = f"{STEAM_API_BASE}/ITwoFactorService/QueryTime/v1/"
ADD_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/AddAuthenticator/v1/"
FINALIZE_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/FinalizeAddAuthenticator/v1/"
SEND_EMAIL_URL = f"{STEAM_API_BASE}/ITwoFactorService/SendEmail/v1/"
REQUEST_TIMEOUT = 30
AUTHENTICATOR_TYPE_MOBILE_APP = "1"
ADD_AUTHENTICATOR_VERSION = "2"


class EnrollmentError(RuntimeError):
    pass


class EnrollmentTransportError(EnrollmentError):
    pass


class AuthenticatorAlreadyPresentError(EnrollmentError):
    pass


class BadActivationCodeError(EnrollmentError):
    pass


@dataclass(frozen=True)
class AddAuthenticatorResult:
    imported: ImportedSteamGuard
    raw: dict[str, Any]


class EnrollmentClient:
    def __init__(self, http: requests.Session | None = None) -> None:
        self.http = http or requests.Session()

    def query_steam_time(self) -> int:
        payload = self._post(QUERY_TIME_URL, params=None, data={})
        response = payload.get("response", payload)
        server_time = response.get("server_time") if isinstance(response, dict) else None
        if server_time is None:
            raise EnrollmentError("Steam time response is missing server_time")
        return int(server_time)

    def add_authenticator(
        self,
        access_token: str,
        steamid64: str,
        account_name: str | None = None,
        device_id: str | None = None,
    ) -> AddAuthenticatorResult:
        device_id = device_id or generate_device_id(steamid64)
        payload = self._post(
            ADD_AUTHENTICATOR_URL,
            params={"access_token": access_token},
            data={
                "steamid": steamid64,
                "authenticator_time": str(self.query_steam_time()),
                "authenticator_type": AUTHENTICATOR_TYPE_MOBILE_APP,
                "device_identifier": device_id,
                "version": ADD_AUTHENTICATOR_VERSION,
            },
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam add-authenticator response is malformed")

        status = int(response.get("status", 0) or 0)
        if status == 29:
            raise AuthenticatorAlreadyPresentError("Steam account already has a mobile authenticator")
        if status != 1:
            raise EnrollmentError(f"Steam rejected add-authenticator request with status {status}")

        shared_secret = _required_str(response, "shared_secret")
        identity_secret = _required_str(response, "identity_secret")
        validate_base64_secret(shared_secret, "shared_secret")
        validate_base64_secret(identity_secret, "identity_secret")

        return AddAuthenticatorResult(
            imported=ImportedSteamGuard(
                account_name=account_name,
                steamid64=steamid64,
                shared_secret=shared_secret,
                identity_secret=identity_secret,
                revocation_code=_optional_str(response.get("revocation_code")),
                device_id=device_id,
            ),
            raw=dict(response),
        )

    def finalize_authenticator(
        self,
        access_token: str,
        steamid64: str,
        shared_secret: str,
        activation_code: str,
        max_attempts: int = 10,
    ) -> None:
        validate_base64_secret(shared_secret, "shared_secret")
        for attempt in range(max_attempts + 1):
            timestamp = self.query_steam_time() + attempt * 30
            payload = self._post(
                FINALIZE_AUTHENTICATOR_URL,
                params={"access_token": access_token},
                data={
                    "steamid": steamid64,
                    "authenticator_code": steam_totp(shared_secret, timestamp),
                    "authenticator_time": str(timestamp),
                    "activation_code": activation_code,
                },
            )
            response = payload.get("response", payload)
            if not isinstance(response, dict):
                raise EnrollmentError("Steam finalize-authenticator response is malformed")

            status = int(response.get("status", 0) or 0)
            if status == 89:
                raise BadActivationCodeError("Steam rejected the activation code")
            if response.get("success") and not response.get("want_more"):
                return
            if response.get("want_more") or status == 88:
                continue
            raise EnrollmentError(f"Steam rejected finalize-authenticator request with status {status}")

        raise EnrollmentError("Steam could not verify authenticator codes during finalization")

    def send_activation_email(self, access_token: str, steamid64: str) -> None:
        self._post(
            SEND_EMAIL_URL,
            params={"access_token": access_token},
            data={
                "steamid": steamid64,
                "include_activation_code": "1",
            },
        )

    def _post(
        self,
        url: str,
        params: dict[str, str] | None,
        data: dict[str, str] | None,
    ) -> dict[str, Any]:
        try:
            response = self.http.post(url, params=params, data=data, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise EnrollmentTransportError("Steam enrollment request failed") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise EnrollmentError("Steam enrollment response is not JSON") from exc
        if not isinstance(payload, dict):
            raise EnrollmentError("Steam enrollment response is malformed")
        return payload


def _required_str(raw: dict[str, Any], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value:
        raise EnrollmentError(f"Steam add-authenticator response is missing {field}")
    return value


def _optional_str(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None
