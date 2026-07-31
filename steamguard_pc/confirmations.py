import re
from collections.abc import Mapping
from typing import Any

import requests

from . import steam_time
from .crypto import confirmation_key
from .models import Confirmation


BASE_URL = "https://steamcommunity.com"
GETLIST_URL = f"{BASE_URL}/mobileconf/getlist"
AJAXOP_URL = f"{BASE_URL}/mobileconf/ajaxop"
MULTIAJAXOP_URL = f"{BASE_URL}/mobileconf/multiajaxop"
REQUEST_TIMEOUT = 15
MOBILE_HEADERS = {"X-Requested-With": "com.valvesoftware.android.steam.community"}
AJAX_HEADERS = {"X-Requested-With": "XMLHttpRequest"}
LIST_ATTEMPTS = (
    ("conf", "android", MOBILE_HEADERS),
    ("list", "react", {"user-agent": "okhttp/4.9.2"}),
)
ACCEPT_ATTEMPTS = (
    ("allow", "android", AJAX_HEADERS),
    ("accept", "react", {"user-agent": "okhttp/4.9.2"}),
)
CANCEL_ATTEMPTS = (
    ("cancel", "android", AJAX_HEADERS),
    ("reject", "react", {"user-agent": "okhttp/4.9.2"}),
)
BATCH_ACCEPT_ATTEMPTS = (
    ("allow", "react", {"user-agent": "okhttp/4.9.2"}),
    ("accept", "react", {"user-agent": "okhttp/4.9.2"}),
)
BATCH_CANCEL_ATTEMPTS = (
    ("cancel", "react", {"user-agent": "okhttp/4.9.2"}),
    ("reject", "react", {"user-agent": "okhttp/4.9.2"}),
)
DETAILS_ATTEMPTS = (
    ("detailspage/{confirmation_id}", "details", "react", {"user-agent": "okhttp/4.9.2"}),
    ("detailspage/{confirmation_id}", "detail", "react", {"user-agent": "okhttp/4.9.2"}),
    ("details/{confirmation_id}", "details{confirmation_id}", "android", MOBILE_HEADERS),
)
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
    mobile_client: str = "android",
) -> dict[str, str | int]:
    timestamp, key = confirmation_key(identity_secret_b64, tag, timestamp)
    return {
        "p": device_id,
        "a": steamid64,
        "k": key,
        "t": timestamp,
        "m": mobile_client,
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


def _request_get(
    session: requests.Session,
    url: str,
    params: Mapping[str, str | int],
    headers: Mapping[str, str],
) -> requests.Response:
    try:
        return session.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        raise ConfirmationTransportError("Steam Community request failed") from exc

def _request_post(
    session: requests.Session,
    url: str,
    data: Mapping[str, object],
    headers: Mapping[str, str],
) -> requests.Response:
    try:
        return session.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        raise ConfirmationTransportError("Steam Community request failed") from exc


def _request_json(
    session: requests.Session,
    url: str,
    params: Mapping[str, str | int],
    headers: Mapping[str, str],
) -> Mapping[str, Any]:
    return _json_payload(_request_get(session, url, params, headers))

def _request_post_json(
    session: requests.Session,
    url: str,
    data: Mapping[str, object],
    headers: Mapping[str, str],
) -> Mapping[str, Any]:
    return _json_payload(_request_post(session, url, data, headers))


def _request_with_attempts(
    session: requests.Session,
    url: str,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    attempts: tuple[tuple[str, str, Mapping[str, str]], ...],
    extra_params: Mapping[str, str] | None = None,
    timestamp: int | None = None,
) -> Mapping[str, Any]:
    last_error: ConfirmationError | None = None
    all_invalid_keys = True
    for tag, mobile_client, headers in attempts:
        params = confirmation_params(steamid64, device_id, identity_secret_b64, tag, timestamp, mobile_client)
        if extra_params is not None:
            params.update(extra_params)
        try:
            return _request_json(session, url, params, headers)
        except (InvalidConfirmationKeyError, ConfirmationRejectedError) as exc:
            last_error = exc
            if not isinstance(exc, InvalidConfirmationKeyError):
                all_invalid_keys = False

    if last_error is None:
        raise ConfirmationFormatError("no confirmation request attempts configured")
    if timestamp is None and all_invalid_keys:
        try:
            server_timestamp = steam_time.query_steam_time()
        except steam_time.SteamTimeError as exc:
            raise last_error from exc
        return _request_with_attempts(
            session,
            url,
            steamid64,
            device_id,
            identity_secret_b64,
            attempts,
            extra_params=extra_params,
            timestamp=server_timestamp,
        )
    raise last_error

def _request_batch_with_attempts(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    attempts: tuple[tuple[str, str, Mapping[str, str]], ...],
    extra_data: Mapping[str, object],
    timestamp: int | None = None,
) -> Mapping[str, Any]:
    last_error: ConfirmationError | None = None
    all_invalid_keys = True
    for tag, mobile_client, headers in attempts:
        data: dict[str, object] = confirmation_params(
            steamid64,
            device_id,
            identity_secret_b64,
            tag,
            timestamp,
            mobile_client,
        )
        data.update(extra_data)
        try:
            return _request_post_json(session, MULTIAJAXOP_URL, data, headers)
        except (InvalidConfirmationKeyError, ConfirmationRejectedError) as exc:
            last_error = exc
            if not isinstance(exc, InvalidConfirmationKeyError):
                all_invalid_keys = False

    if last_error is None:
        raise ConfirmationFormatError("no confirmation batch request attempts configured")
    if timestamp is None and all_invalid_keys:
        try:
            server_timestamp = steam_time.query_steam_time()
        except steam_time.SteamTimeError as exc:
            raise last_error from exc
        return _request_batch_with_attempts(
            session,
            steamid64,
            device_id,
            identity_secret_b64,
            attempts,
            extra_data,
            timestamp=server_timestamp,
        )
    raise last_error


def _request_details_html(
    session: requests.Session,
    url: str,
    params: Mapping[str, str | int],
    headers: Mapping[str, str],
) -> str:

    response = _request_get(session, url, params, headers)
    content_type = response.headers.get("content-type", "")
    text = response.text or ""
    if "json" in content_type.casefold() or text.lstrip().startswith("{"):
        payload = _json_payload(response)
        html = payload.get("html")
        if isinstance(html, str):
            return html
        raise ConfirmationFormatError("confirmation details response is missing html")

    text = response.text or ""
    if INCORRECT_CODES_MESSAGE in text:
        raise InvalidConfirmationKeyError(INCORRECT_CODES_MESSAGE)
    try:
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ConfirmationTransportError("Steam Community request failed") from exc
    if text:
        return text
    raise ConfirmationFormatError("confirmation details response is missing html")


def get_confirmations(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    timestamp: int | None = None,
) -> list[Confirmation]:
    payload = _request_with_attempts(
        session,
        GETLIST_URL,
        steamid64,
        device_id,
        identity_secret_b64,
        LIST_ATTEMPTS,
        timestamp=timestamp,
    )
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
    attempts = ACCEPT_ATTEMPTS if accept else CANCEL_ATTEMPTS
    op = "allow" if accept else "cancel"
    payload = _request_with_attempts(
        session,
        AJAXOP_URL,
        steamid64,
        device_id,
        identity_secret_b64,
        attempts,
        extra_params={"op": op, "cid": confirmation.id, "ck": confirmation.nonce},
        timestamp=timestamp,
    )
    return payload.get("success") is True

def respond_to_confirmations(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    confirmations: list[Confirmation],
    accept: bool,
    timestamp: int | None = None,
) -> bool:
    if not confirmations:
        raise ValueError("no confirmations selected")

    op = "allow" if accept else "cancel"
    attempts = BATCH_ACCEPT_ATTEMPTS if accept else BATCH_CANCEL_ATTEMPTS
    payload = _request_batch_with_attempts(
        session,
        steamid64,
        device_id,
        identity_secret_b64,
        attempts,
        extra_data={
            "op": op,
            "cid": [item.id for item in confirmations],
            "ck": [item.nonce for item in confirmations],
        },
        timestamp=timestamp,
    )
    return payload.get("success") is True


def respond_to_confirmation_ids(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    confirmation_ids: list[str],
    accept: bool,
) -> list[Confirmation]:
    if not confirmation_ids:
        raise ValueError("no confirmations selected")

    seen: set[str] = set()
    for confirmation_id in confirmation_ids:
        if confirmation_id in seen:
            raise ValueError(f"duplicate confirmation id: {confirmation_id}")
        seen.add(confirmation_id)

    current = get_confirmations(session, steamid64, device_id, identity_secret_b64)
    targets: list[Confirmation] = []
    for confirmation_id in confirmation_ids:
        target = next((item for item in current if item.id == confirmation_id), None)
        if target is None:
            raise ConfirmationNotFoundError(f"confirmation {confirmation_id} not found")
        targets.append(target)

    if not respond_to_confirmations(
        session,
        steamid64,
        device_id,
        identity_secret_b64,
        targets,
        accept,
    ):
        raise ConfirmationRejectedError("Steam rejected the confirmation batch request")

    refreshed = get_confirmations(session, steamid64, device_id, identity_secret_b64)
    refreshed_ids = {item.id for item in refreshed}
    remaining = [confirmation_id for confirmation_id in confirmation_ids if confirmation_id in refreshed_ids]
    if remaining:
        ids = ", ".join(remaining)
        raise ConfirmationStillPresentError(f"confirmations still pending after action: {ids}")

    return targets


def get_confirmation_details_html(
    session: requests.Session,
    steamid64: str,
    device_id: str,
    identity_secret_b64: str,
    confirmation_id: str,
    timestamp: int | None = None,
) -> str:
    last_error: ConfirmationError | None = None
    all_invalid_keys = True
    for path_template, tag_template, mobile_client, headers in DETAILS_ATTEMPTS:
        path = path_template.format(confirmation_id=confirmation_id)
        tag = tag_template.format(confirmation_id=confirmation_id)
        params = confirmation_params(steamid64, device_id, identity_secret_b64, tag, timestamp, mobile_client)
        try:
            return _request_details_html(session, f"{BASE_URL}/mobileconf/{path}", params, headers)
        except (InvalidConfirmationKeyError, ConfirmationRejectedError) as exc:
            last_error = exc
            if not isinstance(exc, InvalidConfirmationKeyError):
                all_invalid_keys = False

    if last_error is None:
        raise ConfirmationFormatError("no confirmation details attempts configured")
    if timestamp is None and all_invalid_keys:
        try:
            server_timestamp = steam_time.query_steam_time()
        except steam_time.SteamTimeError as exc:
            raise last_error from exc
        return get_confirmation_details_html(
            session,
            steamid64,
            device_id,
            identity_secret_b64,
            confirmation_id,
            timestamp=server_timestamp,
        )
    raise last_error


def trade_offer_id_from_details_html(html: str) -> str | None:
    match = re.search(r'id=["\']tradeoffer_(\d+)["\']', html)
    return match.group(1) if match else None


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
