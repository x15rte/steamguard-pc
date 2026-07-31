from collections.abc import Mapping
from typing import Any

import requests

from .crypto import confirmation_key
from .models import Confirmation


BASE_URL = "https://steamcommunity.com"
GETLIST_URL = f"{BASE_URL}/mobileconf/getlist"
AJAXOP_URL = f"{BASE_URL}/mobileconf/ajaxop"
REQUEST_TIMEOUT = 15
LIST_TAG = "conf"
ACCEPT_TAG = "allow"
CANCEL_TAG = "cancel"
MOBILE_HEADERS = {"X-Requested-With": "com.valvesoftware.android.steam.community"}
AJAX_HEADERS = {"X-Requested-With": "XMLHttpRequest"}
INCORRECT_CODES_MESSAGE = "incorrect Steam Guard codes"


class ConfirmationError(RuntimeError):
    pass


class ConfirmationTransportError(ConfirmationError):
    pass


class ConfirmationFormatError(ConfirmationError):
    pass


class NeedAuthenticationError(ConfirmationError):
    pass


class InvalidConfirmationKeyError(ConfirmationError):
    pass


class ConfirmationRejectedError(ConfirmationError):
    pass


class ConfirmationNotFoundError(ConfirmationError):
    pass


class ConfirmationStillPresentError(ConfirmationError):
    pass


def confirmation_params(
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    tag: str,
    timestamp: int | None = None,
) -> dict[str, str | int]:
    timestamp, key = confirmation_key(identity_secret_b64, tag, timestamp)
    return {
        "p": device_id,
        "a": steamid64,
        "k": key,
        "t": timestamp,
        "m": "android",
        "tag": tag,
    }


def _required_str(raw: Mapping[str, object], field: str) -> str:
    value = raw.get(field)
    if value is None or value == "":
        raise ConfirmationFormatError(f"confirmation item missing {field}")
    return str(value)


def confirmation_from_api(raw: dict[str, object]) -> Confirmation:
    confirmation_id = _required_str(raw, "id")
    nonce = _required_str(raw, "nonce")
    summary = raw.get("summary")
    if not isinstance(summary, (str, list)):
        summary = None

    creation_time = raw.get("creation_time")
    if not isinstance(creation_time, int):
        creation_time = None

    return Confirmation(
        id=confirmation_id,
        nonce=nonce,
        creator_id=str(raw["creator_id"]) if raw.get("creator_id") is not None else None,
        type=raw.get("type") if isinstance(raw.get("type"), (str, int)) else None,
        type_name=str(raw["type_name"]) if raw.get("type_name") is not None else None,
        headline=str(raw["headline"]) if raw.get("headline") is not None else None,
        summary=summary,
        creation_time=creation_time,
        raw=dict(raw),
    )


def _message(payload: Mapping[str, Any]) -> str:
    for field in ("message", "detail"):
        value = payload.get(field)
        if isinstance(value, str) and value:
            return value
    return "Steam rejected the confirmation request"


def _raise_for_payload_failure(payload: Mapping[str, Any], response_text: str = "") -> None:
    if INCORRECT_CODES_MESSAGE in response_text:
        raise InvalidConfirmationKeyError(INCORRECT_CODES_MESSAGE)

    message = _message(payload)
    if INCORRECT_CODES_MESSAGE in message:
        raise InvalidConfirmationKeyError(INCORRECT_CODES_MESSAGE)

    if payload.get("needauth") is True:
        raise NeedAuthenticationError("Steam Community session expired; refresh cookies")

    if payload.get("success") is False:
        raise ConfirmationRejectedError(message)


def _json_payload(response: requests.Response) -> Mapping[str, Any]:
    text = response.text or ""
    if INCORRECT_CODES_MESSAGE in text:
        raise InvalidConfirmationKeyError(INCORRECT_CODES_MESSAGE)

    try:
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ConfirmationTransportError("Steam Community request failed") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise ConfirmationFormatError("invalid Steam confirmation response") from exc

    if not isinstance(payload, dict):
        raise ConfirmationFormatError("invalid Steam confirmation response")

    _raise_for_payload_failure(payload, text)
    return payload


def _request_json(
    session: requests.Session,
    url: str,
    params: Mapping[str, str | int],
    headers: Mapping[str, str],
) -> Mapping[str, Any]:
    try:
        response = session.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        raise ConfirmationTransportError("Steam Community request failed") from exc
    return _json_payload(response)


def get_confirmations(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    timestamp: int | None = None,
) -> list[Confirmation]:
    params = confirmation_params(steamid64, device_id, identity_secret_b64, LIST_TAG, timestamp)
    payload = _request_json(session, GETLIST_URL, params, MOBILE_HEADERS)
    confirmations = payload.get("conf", [])
    if confirmations is None:
        return []
    if not isinstance(confirmations, list):
        raise ConfirmationFormatError("confirmation list is not an array")

    parsed: list[Confirmation] = []
    for item in confirmations:
        if not isinstance(item, dict):
            raise ConfirmationFormatError("confirmation item is not an object")
        parsed.append(confirmation_from_api(item))
    return parsed


def respond_to_confirmation(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    confirmation: Confirmation,
    accept: bool,
    timestamp: int | None = None,
) -> bool:
    tag = ACCEPT_TAG if accept else CANCEL_TAG
    op = "allow" if accept else "cancel"
    params = confirmation_params(steamid64, device_id, identity_secret_b64, tag, timestamp)
    params.update(
        {
            "op": op,
            "cid": confirmation.id,
            "ck": confirmation.nonce,
        }
    )
    payload = _request_json(session, AJAXOP_URL, params, AJAX_HEADERS)
    return payload.get("success") is True


def respond_to_confirmation_id(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    confirmation_id: str,
    accept: bool,
) -> Confirmation:
    current = get_confirmations(session, steamid64, device_id, identity_secret_b64)
    target = next((item for item in current if item.id == confirmation_id), None)
    if target is None:
        raise ConfirmationNotFoundError(f"confirmation {confirmation_id} not found")

    if not respond_to_confirmation(
        session,
        steamid64,
        device_id,
        identity_secret_b64,
        target,
        accept,
    ):
        raise ConfirmationRejectedError("Steam rejected the confirmation request")

    refreshed = get_confirmations(session, steamid64, device_id, identity_secret_b64)
    if any(item.id == confirmation_id for item in refreshed):
        raise ConfirmationStillPresentError(
            f"confirmation {confirmation_id} is still pending after action"
        )

    return target
