from dataclasses import dataclass
from typing import Any

import requests

from . import steam_time
from .crypto import generate_device_id, steam_totp, validate_base64_secret
from .models import ImportedSteamGuard


STEAM_API_BASE = "https://api.steampowered.com"
ADD_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/AddAuthenticator/v1/"
FINALIZE_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/FinalizeAddAuthenticator/v1/"
SEND_EMAIL_URL = f"{STEAM_API_BASE}/ITwoFactorService/SendEmail/v1/"
CREATE_EMERGENCY_CODES_URL = f"{STEAM_API_BASE}/ITwoFactorService/CreateEmergencyCodes/v1/"
REMOVE_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/RemoveAuthenticator/v1/"
REVOCATION_REASON_USER_REQUESTED = "1"
STEAM_GUARD_SCHEME_EMAIL = "1"
REQUEST_TIMEOUT = 30
AUTHENTICATOR_TYPE_MOBILE_APP = "1"
ADD_AUTHENTICATOR_VERSION = "2"
SEND_EMAIL_TYPE_STEAM_GUARD_ACTIVATION = "2"
MOBILE_APP_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 9; Valve Steam App Version/3)"


class EnrollmentError(RuntimeError):
    pass


class EnrollmentTransportError(EnrollmentError):
    pass


class AuthenticatorAlreadyPresentError(EnrollmentError):
    pass

class PhoneNumberRequiredError(EnrollmentError):
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
        return steam_time.query_steam_time(self.http)

    def add_authenticator(
        self,
        access_token: str,
        steamid64: str,
        account_name: str | None = None,
        device_id: str | None = None,
        sms_phone_id: str | None = None,
    ) -> AddAuthenticatorResult:
        device_id = device_id or generate_device_id(steamid64)
        data = {
            "steamid": steamid64,
            "authenticator_time": str(self.query_steam_time()),
            "authenticator_type": AUTHENTICATOR_TYPE_MOBILE_APP,
            "device_identifier": device_id,
            "version": ADD_AUTHENTICATOR_VERSION,
        }
        if sms_phone_id:
            data["sms_phone_id"] = sms_phone_id
        payload = self._post(
            ADD_AUTHENTICATOR_URL,
            params={"access_token": access_token},
            data=data,
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam add-authenticator response is malformed")

        status = int(response.get("status", 0) or 0)

        if status == 2:
            raise PhoneNumberRequiredError("Steam account needs a verified SMS-capable phone number before authenticator enrollment")
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
                serial_number=_optional_str(response.get("serial_number")),
                token_gid=_optional_str(response.get("token_gid")),
                uri=_optional_str(response.get("uri")),
            ),
            raw=dict(response),
        )

    def finalize_authenticator(
        self,
        access_token: str,
        steamid64: str,
        shared_secret: str,
        activation_code: str,
        validate_sms_code: bool = True,
        max_attempts: int = 10,
    ) -> None:
        validate_base64_secret(shared_secret, "shared_secret")
        next_timestamp: int | None = None
        for _ in range(max_attempts + 1):
            timestamp = next_timestamp if next_timestamp is not None else self.query_steam_time()
            payload = self._post(
                FINALIZE_AUTHENTICATOR_URL,
                params={"access_token": access_token},
                data={
                    "steamid": steamid64,
                    "authenticator_code": steam_totp(shared_secret, timestamp),
                    "authenticator_time": str(timestamp),
                    "activation_code": activation_code,
                    **({"validate_sms_code": "1"} if validate_sms_code else {}),
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
                server_time = response.get("server_time")
                if server_time is None:
                    next_timestamp = timestamp + 30
                else:
                    try:
                        next_timestamp = int(server_time) + 30
                    except (TypeError, ValueError):
                        next_timestamp = timestamp + 30
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
                "email_type": SEND_EMAIL_TYPE_STEAM_GUARD_ACTIVATION,
            },
        )

    def create_emergency_codes(self, access_token: str, code: str | None = None) -> list[str] | None:
        data = {} if code is None else {"code": code}
        payload = self._post(
            CREATE_EMERGENCY_CODES_URL,
            params={"access_token": access_token},
            data=data,
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam emergency-code response is malformed")

        codes = response.get("codes") or response.get("emergency_codes")
        if codes is None and code is None:
            return None
        if not isinstance(codes, list) or not all(isinstance(item, str) and item for item in codes):
            raise EnrollmentError("Steam emergency-code response is missing codes")
        return codes

    def remove_authenticator(
        self,
        access_token: str,
        revocation_code: str,
        steamguard_scheme: str = STEAM_GUARD_SCHEME_EMAIL,
    ) -> None:
        stripped_revocation_code = revocation_code.strip()
        if not stripped_revocation_code:
            raise ValueError("revocation_code is required")

        payload = self._post(
            REMOVE_AUTHENTICATOR_URL,
            params={"access_token": access_token},
            data={
                "revocation_code": stripped_revocation_code,
                "revocation_reason": REVOCATION_REASON_USER_REQUESTED,
                "steamguard_scheme": str(steamguard_scheme),
            },
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam remove-authenticator response is malformed")

        if response.get("success"):
            return

        attempts = response.get("revocation_attempts_remaining")
        if (isinstance(attempts, int) and not isinstance(attempts, bool)) or (isinstance(attempts, str) and attempts.isdecimal()):
            raise EnrollmentError(f"Steam rejected remove-authenticator request ({attempts} revocation-code attempts remaining)")
        raise EnrollmentError("Steam rejected remove-authenticator request")

    def _post(
        self,
        url: str,
        params: dict[str, str] | None,
        data: dict[str, str] | None,
    ) -> dict[str, Any]:
        try:
            response = self.http.post(url, params=params, data=data, headers={"User-Agent": MOBILE_APP_USER_AGENT}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise EnrollmentTransportError("Steam two-factor request failed") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise EnrollmentError("Steam two-factor response is not JSON") from exc
        if not isinstance(payload, dict):
            raise EnrollmentError("Steam two-factor response is malformed")
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
