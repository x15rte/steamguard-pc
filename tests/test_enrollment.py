from urllib.parse import parse_qs

import pytest

from steamguard_pc.crypto import steam_totp
from steamguard_pc.enrollment import (
    ADD_AUTHENTICATOR_URL,
    FINALIZE_AUTHENTICATOR_URL,
    QUERY_TIME_URL,
    AuthenticatorAlreadyPresentError,
    EnrollmentClient,
    PhoneNumberRequiredError,
)


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
DEVICE_ID = "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"


def request_form(request):
    return {key: values[0] for key, values in parse_qs(request.text).items()}


def test_add_authenticator_returns_imported_guard(requests_mock):
    requests_mock.post(QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(
        ADD_AUTHENTICATOR_URL,
        json={
            "response": {
                "status": 1,
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
                "revocation_code": "R12345",
            }
        },
    )

    result = EnrollmentClient().add_authenticator("access-token", STEAMID64, "fixture", DEVICE_ID)

    assert result.imported.steamid64 == STEAMID64
    assert result.imported.account_name == "fixture"
    assert result.imported.shared_secret == SHARED_SECRET
    assert result.imported.identity_secret == IDENTITY_SECRET
    assert result.imported.revocation_code == "R12345"
    assert result.imported.device_id == DEVICE_ID
    form = request_form(requests_mock.request_history[-1])
    assert form["steamid"] == STEAMID64
    assert form["authenticator_time"] == "1700000000"
    assert form["authenticator_type"] == "1"
    assert form["device_identifier"] == DEVICE_ID


@pytest.mark.parametrize(
    ("status", "exc"),
    [
        (2, PhoneNumberRequiredError),
        (29, AuthenticatorAlreadyPresentError),
    ],
)
def test_add_authenticator_maps_status_failures(requests_mock, status, exc):
    requests_mock.post(QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(ADD_AUTHENTICATOR_URL, json={"response": {"status": status}})

    with pytest.raises(exc):
        EnrollmentClient().add_authenticator("access-token", STEAMID64, "fixture", DEVICE_ID)


def test_finalize_authenticator_sends_totp_and_activation_code(requests_mock):
    requests_mock.post(QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(FINALIZE_AUTHENTICATOR_URL, json={"response": {"success": True, "want_more": False, "status": 1}})

    EnrollmentClient().finalize_authenticator("access-token", STEAMID64, SHARED_SECRET, "12345")

    form = request_form(requests_mock.request_history[-1])
    assert form["steamid"] == STEAMID64
    assert form["authenticator_code"] == steam_totp(SHARED_SECRET, 1700000000)
    assert form["authenticator_time"] == "1700000000"
    assert form["activation_code"] == "12345"
    assert form["validate_sms_code"] == "1"
