import pytest
import requests

from steamguard_pc.confirmations import (
    AJAXOP_URL,
    GETLIST_URL,
    Confirmation,
    ConfirmationFormatError,
    ConfirmationRejectedError,
    ConfirmationStillPresentError,
    InvalidConfirmationKeyError,
    NeedAuthenticationError,
    confirmation_params,
    get_confirmations,
    respond_to_confirmation,
    respond_to_confirmation_id,
)


IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
DEVICE_ID = "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"
ITEM_ONE = {
    "id": "1",
    "nonce": "nonce-1",
    "creator_id": "creator-1",
    "type": 2,
    "type_name": "Trade",
    "headline": "Trade offer",
    "summary": ["line one", "line two"],
    "creation_time": 1700000000,
}
ITEM_TWO = {
    "id": "2",
    "nonce": "nonce-2",
    "creator_id": "creator-2",
    "type": "market",
    "type_name": "Market listing",
    "headline": "Market sale",
    "summary": "Sell item",
    "creation_time": 1700000001,
}


def test_confirmation_params_exact_fields():
    assert confirmation_params(STEAMID64, DEVICE_ID, IDENTITY_SECRET, "conf", 1700000000) == {
        "p": DEVICE_ID,
        "a": STEAMID64,
        "k": "6eXMXFho61EmjoiIvP/WlyItlCU=",
        "t": 1700000000,
        "m": "android",
        "tag": "conf",
    }


def test_get_confirmations_success_preserves_fields(requests_mock):
    requests_mock.get(GETLIST_URL, json={"success": True, "conf": [ITEM_ONE, ITEM_TWO]})

    confirmations = get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)

    assert len(confirmations) == 2
    first = confirmations[0]
    assert first.id == "1"
    assert first.nonce == "nonce-1"
    assert first.creator_id == "creator-1"
    assert first.type == 2
    assert first.type_name == "Trade"
    assert first.headline == "Trade offer"
    assert first.summary == ["line one", "line two"]
    assert first.creation_time == 1700000000
    assert first.raw == ITEM_ONE
    assert requests_mock.last_request.qs["tag"] == ["conf"]


def test_get_confirmations_needauth_raises(requests_mock):
    requests_mock.get(GETLIST_URL, json={"needauth": True})

    with pytest.raises(NeedAuthenticationError):
        get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)


def test_get_confirmations_invalid_json_raises(requests_mock):
    requests_mock.get(GETLIST_URL, text="not-json")

    with pytest.raises(ConfirmationFormatError):
        get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)


def test_get_confirmations_success_false_raises_message(requests_mock):
    requests_mock.get(GETLIST_URL, json={"success": False, "message": "denied by Steam"})

    with pytest.raises(ConfirmationRejectedError, match="denied by Steam"):
        get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)


@pytest.mark.parametrize(
    "response_kwargs",
    [
        {"text": "incorrect Steam Guard codes"},
        {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
    ],
)
def test_get_confirmations_incorrect_codes_raises_invalid_key(requests_mock, response_kwargs):
    requests_mock.get(GETLIST_URL, **response_kwargs)

    with pytest.raises(InvalidConfirmationKeyError):
        get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)


def test_approve_uses_allow_operation_and_key_tag(requests_mock):
    requests_mock.get(AJAXOP_URL, json={"success": True})
    confirmation = Confirmation(id="1", nonce="nonce-1")

    assert respond_to_confirmation(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        confirmation,
        accept=True,
        timestamp=1700000000,
    ) is True
    query = requests_mock.last_request.qs
    assert query["op"] == ["allow"]
    assert query["tag"] == ["allow"]
    assert query["cid"] == ["1"]
    assert query["ck"] == ["nonce-1"]


def test_cancel_uses_cancel_operation_and_key_tag(requests_mock):
    requests_mock.get(AJAXOP_URL, json={"success": True})
    confirmation = Confirmation(id="1", nonce="nonce-1")

    assert respond_to_confirmation(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        confirmation,
        accept=False,
        timestamp=1700000000,
    ) is True
    query = requests_mock.last_request.qs
    assert query["op"] == ["cancel"]
    assert query["tag"] == ["cancel"]
    assert query["cid"] == ["1"]
    assert query["ck"] == ["nonce-1"]


def test_respond_to_confirmation_id_refreshes_before_and_after_success(requests_mock):
    requests_mock.get(
        GETLIST_URL,
        [
            {"json": {"success": True, "conf": [ITEM_ONE]}},
            {"json": {"success": True, "conf": []}},
        ],
    )
    requests_mock.get(AJAXOP_URL, json={"success": True})

    acted = respond_to_confirmation_id(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, "1", True)

    assert acted.id == "1"
    assert [request.path for request in requests_mock.request_history] == [
        "/mobileconf/getlist",
        "/mobileconf/ajaxop",
        "/mobileconf/getlist",
    ]


def test_respond_to_confirmation_id_raises_when_target_remains(requests_mock):
    requests_mock.get(
        GETLIST_URL,
        [
            {"json": {"success": True, "conf": [ITEM_ONE]}},
            {"json": {"success": True, "conf": [ITEM_ONE]}},
        ],
    )
    requests_mock.get(AJAXOP_URL, json={"success": True})

    with pytest.raises(ConfirmationStillPresentError, match="^confirmation 1 is still pending after action$"):
        respond_to_confirmation_id(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, "1", True)
