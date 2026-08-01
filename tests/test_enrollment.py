from urllib.parse import parse_qs

import pytest

from steamguard_pc import steam_time
from steamguard_pc.crypto import steam_totp
from steamguard_pc.enrollment import (
    ADD_AUTHENTICATOR_URL,
    FINALIZE_AUTHENTICATOR_URL,
    CREATE_EMERGENCY_CODES_URL,
    SEND_EMAIL_URL,
    MOBILE_APP_USER_AGENT,
    AuthenticatorAlreadyPresentError,
    EnrollmentClient,
    EnrollmentError,
    PhoneNumberRequiredError,
)


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
DEVICE_ID = "android:6d3f10d9-6369-a1ae-97a0-94df28b95192"


def request_form(request):
    return {key: values[0] for key, values in parse_qs(request.text).items()}


def test_add_authenticator_returns_imported_guard(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(
        ADD_AUTHENTICATOR_URL,
        json={
            "response": {
                "status": 1,
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
                "revocation_code": "R12345",
                "serial_number": "serial-1",
                "token_gid": "token-gid-1",
                "uri": "otpauth://totp/steam?secret=fixture",
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
    assert result.imported.serial_number == "serial-1"
    assert result.imported.token_gid == "token-gid-1"
    assert result.imported.uri == "otpauth://totp/steam?secret=fixture"
    form = request_form(requests_mock.request_history[-1])
    assert form["steamid"] == STEAMID64
    assert form["authenticator_time"] == "1700000000"
    assert form["authenticator_type"] == "1"
    assert form["device_identifier"] == DEVICE_ID
    assert form["version"] == "2"
    assert "sms_phone_id" not in form
    assert requests_mock.request_history[-1].headers["User-Agent"] == MOBILE_APP_USER_AGENT


def test_add_authenticator_can_request_sms_phone_flow(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(
        ADD_AUTHENTICATOR_URL,
        json={"response": {"status": 1, "shared_secret": SHARED_SECRET, "identity_secret": IDENTITY_SECRET}},
    )

    EnrollmentClient().add_authenticator("access-token", STEAMID64, "fixture", DEVICE_ID, sms_phone_id="1")

    form = request_form(requests_mock.request_history[-1])
    assert form["sms_phone_id"] == "1"


@pytest.mark.parametrize(
    ("status", "exc"),
    [
        (2, PhoneNumberRequiredError),
        (29, AuthenticatorAlreadyPresentError),
    ],
)
def test_add_authenticator_maps_status_failures(requests_mock, status, exc):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(ADD_AUTHENTICATOR_URL, json={"response": {"status": status}})

    with pytest.raises(exc):
        EnrollmentClient().add_authenticator("access-token", STEAMID64, "fixture", DEVICE_ID)


def test_finalize_authenticator_sends_totp_and_activation_code(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(FINALIZE_AUTHENTICATOR_URL, json={"response": {"success": True, "want_more": False, "status": 1}})

    EnrollmentClient().finalize_authenticator("access-token", STEAMID64, SHARED_SECRET, "12345")

    form = request_form(requests_mock.request_history[-1])
    assert form["steamid"] == STEAMID64
    assert form["authenticator_code"] == steam_totp(SHARED_SECRET, 1700000000)
    assert form["authenticator_time"] == "1700000000"
    assert form["activation_code"] == "12345"
    assert form["validate_sms_code"] == "1"


def test_finalize_authenticator_uses_response_server_time_for_retry(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(
        FINALIZE_AUTHENTICATOR_URL,
        [
            {"json": {"response": {"success": False, "want_more": True, "status": 88, "server_time": 1700000090}}},
            {"json": {"response": {"success": True, "want_more": False, "status": 1}}},
        ],
    )

    EnrollmentClient().finalize_authenticator("access-token", STEAMID64, SHARED_SECRET, "12345")

    finalize_forms = [request_form(request) for request in requests_mock.request_history if request.url.startswith(FINALIZE_AUTHENTICATOR_URL)]
    assert [form["authenticator_time"] for form in finalize_forms] == ["1700000000", "1700000120"]
    assert finalize_forms[1]["authenticator_code"] == steam_totp(SHARED_SECRET, 1700000120)



def test_finalize_authenticator_can_skip_sms_validation_for_email_code(requests_mock):
    requests_mock.post(steam_time.QUERY_TIME_URL, json={"response": {"server_time": 1700000000}})
    requests_mock.post(FINALIZE_AUTHENTICATOR_URL, json={"response": {"success": True, "want_more": False, "status": 1}})

    EnrollmentClient().finalize_authenticator("access-token", STEAMID64, SHARED_SECRET, "12345", validate_sms_code=False)

    form = request_form(requests_mock.request_history[-1])
    assert "validate_sms_code" not in form


def test_send_activation_email_requests_activation_code(requests_mock):
    requests_mock.post(SEND_EMAIL_URL, json={"response": {"success": True}})

    EnrollmentClient().send_activation_email("access-token", STEAMID64)

    request = requests_mock.request_history[-1]
    assert request.qs["access_token"] == ["access-token"]
    form = request_form(request)
    assert form["steamid"] == STEAMID64
    assert form["include_activation_code"] == "1"
    assert form["email_type"] == "2"



def test_create_emergency_codes_requests_confirmation_code(requests_mock):
    requests_mock.post(CREATE_EMERGENCY_CODES_URL, json={"response": {"status": 1}})

    assert EnrollmentClient().create_emergency_codes("access-token") is None

    request = requests_mock.request_history[-1]
    assert request.qs["access_token"] == ["access-token"]
    assert "code" not in request_form(request)


def test_create_emergency_codes_returns_codes(requests_mock):
    requests_mock.post(CREATE_EMERGENCY_CODES_URL, json={"response": {"codes": ["12345678", "87654321"]}})

    codes = EnrollmentClient().create_emergency_codes("access-token", code="13579")

    assert codes == ["12345678", "87654321"]
    request = requests_mock.request_history[-1]
    assert request_form(request)["code"] == "13579"


def test_create_emergency_codes_rejects_missing_codes(requests_mock):
    requests_mock.post(CREATE_EMERGENCY_CODES_URL, json={"response": {}})

    with pytest.raises(EnrollmentError, match="^Steam emergency-code response is missing codes$"):
        EnrollmentClient().create_emergency_codes("access-token", code="13579")
