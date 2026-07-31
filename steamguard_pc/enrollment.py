from dataclasses import dataclass
from typing import Any

import requests

from .crypto import generate_device_id, steam_totp, validate_base64_secret
from .models import ImportedSteamGuard


STEAM_API_BASE = "https://api.steampowered.com"
QUERY_TIME_URL = f"{STEAM_API_BASE}/ITwoFactorService/QueryTime/v1/"
ADD_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/AddAuthenticator/v1/"
FINALIZE_AUTHENTICATOR_URL = f"{STEAM_API_BASE}/ITwoFactorService/FinalizeAddAuthenticator/v1/"
GET_COUNTRY_URL = f"{STEAM_API_BASE}/IUserAccountService/GetUserCountry/v1/"
SET_PHONE_URL = f"{STEAM_API_BASE}/IPhoneService/SetAccountPhoneNumber/v1/"
WAITING_EMAIL_URL = f"{STEAM_API_BASE}/IPhoneService/IsAccountWaitingForEmailConfirmation/v1/"
SEND_PHONE_CODE_URL = f"{STEAM_API_BASE}/IPhoneService/SendPhoneVerificationCode/v1/"
REQUEST_TIMEOUT = 30
AUTHENTICATOR_TYPE_MOBILE_APP = "1"
DEFAULT_SMS_PHONE_ID = "1"


class EnrollmentError(RuntimeError):
    pass


class EnrollmentTransportError(EnrollmentError):
    pass


class PhoneNumberRequiredError(EnrollmentError):
    pass


class AuthenticatorAlreadyPresentError(EnrollmentError):
    pass


class BadActivationCodeError(EnrollmentError):
    pass


@dataclass(frozen=True)
class AddAuthenticatorResult:
    imported: ImportedSteamGuard
    raw: dict[str, Any]


@dataclass(frozen=True)
class SetPhoneNumberResult:
    confirmation_email_address: str | None = None
    phone_number_formatted: str | None = None


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
                "sms_phone_id": DEFAULT_SMS_PHONE_ID,
            },
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam add-authenticator response is malformed")

        status = int(response.get("status", 0) or 0)
        if status == 2:
            raise PhoneNumberRequiredError("Steam account needs a verified phone number before adding an authenticator")
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
                    "validate_sms_code": "1",
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

    def get_user_country(self, access_token: str, steamid64: str) -> str:
        payload = self._post(
            GET_COUNTRY_URL,
            params={"access_token": access_token},
            data={"steamid": steamid64},
        )
        response = payload.get("response", payload)
        country = response.get("country") if isinstance(response, dict) else None
        if not country:
            raise EnrollmentError("Steam country response is missing country")
        return str(country)

    def set_account_phone_number(
        self,
        access_token: str,
        phone_number: str,
        phone_country_code: str,
    ) -> SetPhoneNumberResult:
        payload = self._post(
            SET_PHONE_URL,
            params={"access_token": access_token},
            data={
                "phone_number": phone_number,
                "phone_country_code": phone_country_code,
            },
        )
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam phone-number response is malformed")
        return SetPhoneNumberResult(
            confirmation_email_address=_optional_str(response.get("confirmation_email_address")),
            phone_number_formatted=_optional_str(response.get("phone_number_formatted")),
        )

    def is_waiting_for_email_confirmation(self, access_token: str) -> bool:
        payload = self._post(WAITING_EMAIL_URL, params={"access_token": access_token}, data={})
        response = payload.get("response", payload)
        if not isinstance(response, dict):
            raise EnrollmentError("Steam email-confirmation response is malformed")
        return bool(response.get("awaiting_email_confirmation"))

    def send_phone_verification_code(self, access_token: str) -> None:
        self._post(SEND_PHONE_CODE_URL, params={"access_token": access_token}, data={})

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
