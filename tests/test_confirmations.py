from urllib.parse import parse_qs
import pytest
import requests
from steamguard_pc import steam_time

from steamguard_pc.confirmations import (
    AJAXOP_URL,
    BASE_URL,
    GETLIST_URL,
    MULTIAJAXOP_URL,
    Confirmation,
    ConfirmationFormatError,
    ConfirmationRejectedError,
    ConfirmationStillPresentError,
    InvalidConfirmationKeyError,
    NeedAuthenticationError,
    confirmation_params,
    confirmation_from_api,
    get_confirmations,
    get_confirmation_details_html,
    respond_to_confirmation,
    respond_to_confirmation_id,
    respond_to_confirmation_ids,
    respond_to_confirmations,
    trade_offer_id_from_details_html,
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


def test_get_confirmations_falls_back_to_current_tag_and_react_client(requests_mock):
    requests_mock.get(
        GETLIST_URL,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": True, "conf": [ITEM_ONE]}},
        ],
    )

    confirmations = get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET, 1700000000)

    assert [item.id for item in confirmations] == ["1"]
    assert [request.qs["tag"][0] for request in requests_mock.request_history] == ["conf", "list"]
    assert [request.qs["m"][0] for request in requests_mock.request_history] == ["react", "react"]


def test_get_confirmations_retries_bad_codes_with_steam_time(monkeypatch, requests_mock):
    monkeypatch.setattr(steam_time, "query_steam_time", lambda: 1700000030)
    requests_mock.get(
        GETLIST_URL,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": True, "conf": [ITEM_ONE]}},
        ],
    )

    confirmations = get_confirmations(requests.Session(), STEAMID64, DEVICE_ID, IDENTITY_SECRET)

    assert [item.id for item in confirmations] == ["1"]
    assert [request.qs["tag"][0] for request in requests_mock.request_history] == ["conf", "list", "conf"]
    assert requests_mock.request_history[-1].qs["t"] == ["1700000030"]


def test_approve_uses_allow_operation_and_accept_key_tag(requests_mock):
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
    assert query["tag"] == ["accept"]
    assert query["cid"] == ["1"]
    assert query["ck"] == ["nonce-1"]


def test_respond_to_confirmation_falls_back_to_legacy_allow_tag(requests_mock):
    requests_mock.get(
        AJAXOP_URL,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": True}},
        ],
    )
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

    assert [request.qs["op"][0] for request in requests_mock.request_history] == ["allow", "allow"]
    assert [request.qs["tag"][0] for request in requests_mock.request_history] == ["accept", "allow"]
    assert [request.qs["ck"][0] for request in requests_mock.request_history] == ["nonce-1", "nonce-1"]


def test_cancel_uses_cancel_operation_and_reject_key_tag(requests_mock):
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
    assert query["tag"] == ["reject"]
    assert query["cid"] == ["1"]
    assert query["ck"] == ["nonce-1"]

def test_respond_to_confirmations_posts_multiajaxop_arrays_with_allow_tag(requests_mock):
    requests_mock.post(MULTIAJAXOP_URL, json={"success": True})
    selected = [confirmation_from_api(ITEM_ONE), confirmation_from_api(ITEM_TWO)]

    assert respond_to_confirmations(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        selected,
        True,
        timestamp=1700000000,
    ) is True

    request = requests_mock.last_request
    assert request.method == "POST"
    form = parse_qs(request.text)
    assert form["cid[]"] == ["1", "2"]
    assert form["ck[]"] == ["nonce-1", "nonce-2"]
    assert form["op"] == ["allow"]
    assert form["tag"] == ["allow"]
    assert form["m"] == ["react"]
    assert request.headers["Origin"] == BASE_URL



def test_respond_to_confirmations_falls_back_to_accept_batch_tag(requests_mock):
    requests_mock.post(
        MULTIAJAXOP_URL,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": True}},
        ],
    )
    selected = [confirmation_from_api(ITEM_ONE), confirmation_from_api(ITEM_TWO)]

    assert respond_to_confirmations(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        selected,
        True,
        timestamp=1700000000,
    ) is True

    assert [parse_qs(request.text)["tag"][0] for request in requests_mock.request_history] == ["allow", "accept"]
    final_body = parse_qs(requests_mock.request_history[-1].text)
    assert final_body["cid[]"] == ["1", "2"]
    assert final_body["ck[]"] == ["nonce-1", "nonce-2"]


def test_respond_to_confirmation_ids_refreshes_before_and_after_batch_success(requests_mock):
    requests_mock.get(
        GETLIST_URL,
        [
            {"json": {"success": True, "conf": [ITEM_ONE, ITEM_TWO]}},
            {"json": {"success": True, "conf": []}},
        ],
    )
    requests_mock.post(MULTIAJAXOP_URL, json={"success": True})

    acted = respond_to_confirmation_ids(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        ["1", "2"],
        True,
    )

    assert [item.id for item in acted] == ["1", "2"]
    assert [request.method for request in requests_mock.request_history] == ["GET", "POST", "GET"]


def test_respond_to_confirmation_ids_rejects_duplicate_ids(requests_mock):
    with pytest.raises(ValueError, match="^duplicate confirmation id: 1$"):
        respond_to_confirmation_ids(
            requests.Session(),
            STEAMID64,
            DEVICE_ID,
            IDENTITY_SECRET,
            ["1", "1"],
            True,
        )

    assert [request.method for request in requests_mock.request_history] == []



def test_confirmation_details_extracts_trade_offer_id(requests_mock):
    details_url = f"{BASE_URL}/mobileconf/detailspage/1"
    html = '<div id="tradeoffer_123456"></div>'
    requests_mock.get(details_url, json={"html": html})

    returned_html = get_confirmation_details_html(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        "1",
        timestamp=1700000000,
    )

    assert returned_html == html
    assert trade_offer_id_from_details_html(returned_html) == "123456"
    assert requests_mock.last_request.qs["tag"] == ["details"]
    assert requests_mock.last_request.qs["m"] == ["react"]


def test_confirmation_details_falls_back_to_detail_tag(requests_mock):
    details_url = f"{BASE_URL}/mobileconf/detailspage/1"
    html = '<div id="tradeoffer_123456"></div>'
    requests_mock.get(
        details_url,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"html": html}},
        ],
    )

    returned_html = get_confirmation_details_html(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        "1",
        timestamp=1700000000,
    )

    assert returned_html == html
    assert [request.qs["tag"][0] for request in requests_mock.request_history] == ["details", "detail"]
    assert [request.qs["m"][0] for request in requests_mock.request_history] == ["react", "react"]


def test_confirmation_details_falls_back_to_mobile_details_path(requests_mock):
    detailspage_url = f"{BASE_URL}/mobileconf/detailspage/1"
    mobile_details_url = f"{BASE_URL}/mobileconf/details/1"
    html = '<div id="tradeoffer_123456"></div>'
    requests_mock.get(
        detailspage_url,
        [
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
            {"json": {"success": False, "message": "incorrect Steam Guard codes"}},
        ],
    )
    requests_mock.get(mobile_details_url, json={"html": html})

    returned_html = get_confirmation_details_html(
        requests.Session(),
        STEAMID64,
        DEVICE_ID,
        IDENTITY_SECRET,
        "1",
        timestamp=1700000000,
    )

    assert returned_html == html
    assert [request.path for request in requests_mock.request_history] == [
        "/mobileconf/detailspage/1",
        "/mobileconf/detailspage/1",
        "/mobileconf/details/1",
    ]
    assert [request.qs["tag"][0] for request in requests_mock.request_history] == ["details", "detail", "details"]
    assert requests_mock.request_history[-1].qs["m"] == ["android"]

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
