import io
import json
from contextlib import contextmanager

import pytest

from steamguard_pc import cli
from steamguard_pc.models import AccountMetadata, Confirmation


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"
REVOCATION_CODE = "R12345"


def test_code_timestamp_prints_deterministic_code(monkeypatch, capsys):
    monkeypatch.setattr(cli.storage, "get_required_secret", lambda steamid64, field: SHARED_SECRET)

    assert cli.main(["code", STEAMID64, "--timestamp", "0"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "CX2MR expires_in=30s",
        "Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.",
    ]


def test_code_steam_time_uses_query_time(monkeypatch, capsys):
    monkeypatch.setattr(cli.storage, "get_required_secret", lambda steamid64, field: SHARED_SECRET)
    monkeypatch.setattr(cli.steam_time, "query_steam_time", lambda: 30)

    assert cli.main(["code", STEAMID64, "--steam-time"]) == 0

    assert capsys.readouterr().out.startswith("57G3M expires_in=30s\n")



def test_top_level_help_is_descriptive(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["-h"])

    assert excinfo.value.code == 0
    output = capsys.readouterr().out
    assert "SteamGuardPC is a Windows-focused Steam Guard helper." in output
    assert "Common workflows:" in output
    assert "revocation-code" in output
    assert "commands:" in output
    assert "setup" in output
    assert "Guided first-run setup." in output
    assert "Run `steamguard-pc COMMAND -h`" in output


def test_revocation_code_requires_exact_phrase(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture"))
    cli.storage.put_secret(STEAMID64, "revocation_code", REVOCATION_CODE)
    monkeypatch.setattr("sys.stdin", io.StringIO("SHOW\n"))

    assert cli.main(["revocation-code", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert "Revocation code display cancelled." in output
    assert REVOCATION_CODE not in output


def test_revocation_code_prints_after_exact_phrase(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture"))
    cli.storage.put_secret(STEAMID64, "revocation_code", REVOCATION_CODE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"SHOW REVOCATION CODE {STEAMID64}\n"))

    assert cli.main(["revocation-code", STEAMID64]) == 0

    output = capsys.readouterr().out
    assert "can remove this authenticator" in output
    assert "not the seven-digit recovery code" in output
    assert "R followed by five digits" in output
    assert f"Steam Guard revocation code for fixture ({STEAMID64}): {REVOCATION_CODE}" in output


def test_recovery_codes_requires_exact_phrase(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture"))

    def refresh_auth_tokens(steamid64):
        raise AssertionError("unexpected token refresh")

    class FailingEnrollmentClient:
        def __init__(self):
            raise AssertionError("unexpected enrollment client")

    monkeypatch.setattr(cli.session, "refresh_auth_tokens", refresh_auth_tokens)
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FailingEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["recovery-codes", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert "Recovery-code creation cancelled." in output
    assert "WRONG" not in output
    assert "12345678" not in output


def test_recovery_codes_requests_confirmation_and_prints_codes(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture"))
    refresh_calls = []

    def refresh_auth_tokens(steamid64):
        refresh_calls.append(steamid64)
        return "access-token", "refresh-token"

    class FakeEnrollmentClient:
        instances = []

        def __init__(self):
            self.calls = []
            self.instances.append(self)

        def create_emergency_codes(self, access_token, code=None):
            self.calls.append((access_token, code))
            assert access_token == "access-token"
            if code is None:
                return None
            assert code == "13579"
            return ["12345678", "87654321"]

    monkeypatch.setattr(cli.session, "refresh_auth_tokens", refresh_auth_tokens)
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FakeEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"CREATE RECOVERY CODES {STEAMID64}\n13579\n"))

    assert cli.main(["recovery-codes", STEAMID64]) == 0

    output = capsys.readouterr().out
    assert "Steam recovery codes are one-time login codes for official Steam recovery prompts." in output
    assert "Creating a new set may replace older emergency codes. Store the new set offline immediately." in output
    assert f"Steam recovery codes for fixture ({STEAMID64}):" in output
    assert "12345678" in output
    assert "87654321" in output
    assert "They are not saved by SteamGuardPC." in output
    assert "13579" not in output
    assert refresh_calls == [STEAMID64]
    assert FakeEnrollmentClient.instances[0].calls == [("access-token", None), ("access-token", "13579")]

def test_import_mafile_does_not_print_secret_values(monkeypatch, tmp_path, capsys):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(
        json.dumps(
            {
                "steamid": STEAMID64,
                "account_name": "fixture",
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
                "revocation_code": REVOCATION_CODE,
                "Session": {
                    "SteamLoginSecure": "secure-cookie",
                    "SessionID": "session-cookie",
                },
            }
        ),
        encoding="utf-8",
    )

    def store_imported_guard(imported):
        assert imported.shared_secret == SHARED_SECRET
        assert imported.identity_secret == IDENTITY_SECRET
        assert imported.revocation_code == REVOCATION_CODE
        assert imported.steam_login_secure == "secure-cookie"
        assert imported.sessionid == "session-cookie"
        return AccountMetadata(
            steamid64=imported.steamid64,
            account_name=imported.account_name,
            device_id=imported.device_id,
            last_imported_at="2026-07-31T00:00:00Z",
        )

    monkeypatch.setattr(cli.storage, "store_imported_guard", store_imported_guard)

    assert cli.main(["import-mafile", str(mafile_path)]) == 0

    printed = capsys.readouterr().out
    assert printed == (
        f"Imported fixture ({STEAMID64})\n"
        f"Steam Guard revocation code was stored. Run `steamguard-pc revocation-code {STEAMID64}` in a private terminal and store it offline.\n"
    )
    for secret in [SHARED_SECRET, IDENTITY_SECRET, REVOCATION_CODE, "secure-cookie", "session-cookie"]:
        assert secret not in printed


def test_cookie_guide_prints_browser_cookie_steps(capsys):
    assert cli.main(["cookie-guide"]) == 0

    output = capsys.readouterr().out
    assert "Application > Storage > Cookies" in output
    assert "steamLoginSecure" in output
    assert "sessionid" in output


def test_find_mafiles_command_prints_candidates(tmp_path, capsys):
    mafiles = tmp_path / "maFiles"
    candidate = mafiles / "account.maFile"
    candidate.parent.mkdir()
    candidate.write_text("{}", encoding="utf-8")

    assert cli.main(["find-mafiles", str(mafiles)]) == 0

    assert capsys.readouterr().out == f"{candidate.resolve()}\n"


def test_setup_imports_mafile_and_skips_cookie_prompts(monkeypatch, tmp_path, capsys):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(
        json.dumps(
            {
                "steamid": STEAMID64,
                "account_name": "fixture",
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
            }
        ),
        encoding="utf-8",
    )

    def store_imported_guard(imported):
        return AccountMetadata(
            steamid64=imported.steamid64,
            account_name=imported.account_name,
            device_id=imported.device_id,
            last_imported_at="2026-07-31T00:00:00Z",
        )

    monkeypatch.setattr(cli.storage, "store_imported_guard", store_imported_guard)

    assert cli.main(["setup", "--mafile", str(mafile_path), "--skip-cookies"]) == 0

    output = capsys.readouterr().out
    assert "SteamGuardPC setup" in output
    assert f"Imported fixture ({STEAMID64})" in output
    assert "Skipped cookie setup." in output
    assert f"Next: steamguard-pc code {STEAMID64}" in output
    for secret in [SHARED_SECRET, IDENTITY_SECRET]:
        assert secret not in output


def test_setup_stores_environment_cookies_without_printing_them(monkeypatch, tmp_path, capsys):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(
        json.dumps(
            {
                "steamid": STEAMID64,
                "account_name": "fixture",
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def store_imported_guard(imported):
        return AccountMetadata(
            steamid64=imported.steamid64,
            account_name=imported.account_name,
            device_id=imported.device_id,
            last_imported_at="2026-07-31T00:00:00Z",
        )

    def save_community_cookies(steamid64, steam_login_secure, sessionid):
        calls.append((steamid64, steam_login_secure, sessionid))

    monkeypatch.setattr(cli.storage, "store_imported_guard", store_imported_guard)
    monkeypatch.setattr(cli.session, "save_community_cookies", save_community_cookies)
    monkeypatch.setenv("STEAMGUARDPC_STEAM_LOGIN_SECURE", "secure-cookie")
    monkeypatch.setenv("STEAMGUARDPC_SESSIONID", "session-cookie")

    assert cli.main(["setup", "--mafile", str(mafile_path)]) == 0

    assert calls == [(STEAMID64, "secure-cookie", "session-cookie")]
    output = capsys.readouterr().out
    assert f"Stored Steam Community cookies for {STEAMID64} from environment variables." in output
    assert "secure-cookie" not in output
    assert "session-cookie" not in output



def test_login_command_stores_tokens_cookies_and_metadata(monkeypatch, keyring_store, capsys):
    result = cli.auth.LoginResult(
        steamid64=STEAMID64,
        account_name="fixture",
        refresh_token="refresh-token",
        access_token="access-token",
        steam_login_secure="secure-cookie",
        sessionid="session-cookie",
    )
    monkeypatch.setattr(cli, "_login_with_prompts", lambda account_name: result)

    assert cli.main(["login", "fixture"]) == 0

    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:refresh_token")] == "refresh-token"
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:access_token")] == "access-token"
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:steamLoginSecure")] == "secure-cookie"
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:sessionid")] == "session-cookie"
    assert f"Signed in and stored Steam Community session for fixture ({STEAMID64})." in capsys.readouterr().out



def test_login_guard_prompt_uses_stored_totp(monkeypatch, keyring_store, capsys):
    cli.storage.put_secret(STEAMID64, "shared_secret", SHARED_SECRET)
    monkeypatch.setattr(cli, "steam_totp", lambda shared_secret: "AUTO1")
    action = cli.auth.GuardAction(type=cli.auth.GUARD_DEVICE_CODE, message="mobile")
    auth_session = cli.auth.AuthSession(
        client_id=1,
        request_id=b"request",
        poll_interval=1.0,
        steamid64=STEAMID64,
    )

    assert cli._code_for_login(action, auth_session) == "AUTO1"

    output = capsys.readouterr().out
    assert output == f"Using stored Steam Guard code for {STEAMID64}.\n"
    assert SHARED_SECRET not in output

def test_enroll_command_stores_generated_secrets_and_finalizes(monkeypatch, keyring_store, capsys):
    result = cli.auth.LoginResult(
        steamid64=STEAMID64,
        account_name="fixture",
        refresh_token="refresh-token",
        access_token="access-token",
        steam_login_secure="secure-cookie",
        sessionid="session-cookie",
    )
    metadata = cli.storage.AccountMetadata(
        steamid64=STEAMID64,
        account_name="fixture",
        device_id="android:fixture",
    )
    calls = []

    class FakeEnrollmentClient:
        def add_authenticator(self, access_token, steamid64, account_name=None, device_id=None):
            calls.append(("add", access_token, steamid64, account_name, device_id))
            imported = cli.mafile.parse_mafile(
                {
                    "steamid": STEAMID64,
                    "account_name": "fixture",
                    "shared_secret": SHARED_SECRET,
                    "identity_secret": IDENTITY_SECRET,
                    "device_id": "android:fixture",
                    "revocation_code": REVOCATION_CODE,
                }
            )
            return cli.enrollment.AddAuthenticatorResult(imported=imported, raw={})

        def finalize_authenticator(self, access_token, steamid64, shared_secret, activation_code):
            calls.append(("finalize", access_token, steamid64, shared_secret, activation_code))


    monkeypatch.setattr(cli, "_login_and_store", lambda account_name: (result, metadata))
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FakeEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"ADD AUTHENTICATOR {STEAMID64}\n12345\n"))

    assert cli.main(["enroll", "fixture"]) == 0

    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:shared_secret")] == SHARED_SECRET
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:identity_secret")] == IDENTITY_SECRET
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:revocation_code")] == REVOCATION_CODE
    assert calls[-1] == ("finalize", "access-token", STEAMID64, SHARED_SECRET, "12345")
    output = capsys.readouterr().out
    assert f"Authenticator added and finalized for fixture ({STEAMID64})." in output
    assert f"Steam Guard revocation code for fixture ({STEAMID64}): {REVOCATION_CODE}" in output
    assert "Store this code offline" in output
    assert "R followed by five digits" in output
    assert output.index("Steam Guard revocation code") < output.index("Steam activation code from email or SMS")
    assert "Steam activation code from email or SMS" in output
    assert "SMS activation code" not in output
    assert SHARED_SECRET not in output
    assert IDENTITY_SECRET not in output

def _patch_confirmation_context(monkeypatch, calls):
    target = Confirmation(
        id="abc",
        nonce="nonce",
        creator_id="creator",
        type_name="Trade",
        headline="Trade offer",
        summary="Summary",
    )
    monkeypatch.setattr(
        cli.storage,
        "load_accounts",
        lambda: {
            STEAMID64: AccountMetadata(
                steamid64=STEAMID64,
                account_name="fixture",
                device_id="android:fixture",
            )
        },
    )
    monkeypatch.setattr(cli.storage, "get_required_secret", lambda steamid64, field: "identity-secret")
    monkeypatch.setattr(cli.session, "get_community_session", lambda steamid64: object())
    monkeypatch.setattr(cli.confirmations, "get_confirmations", lambda *args, **kwargs: [target])
    monkeypatch.setattr(
        cli.confirmations,
        "get_confirmation_details_html",
        lambda *args, **kwargs: '<div id="tradeoffer_123456"></div>',
    )

    @contextmanager
    def account_operation_lock(steamid64):
        yield

    monkeypatch.setattr(cli.operation_lock, "account_operation_lock", account_operation_lock)

    def respond_to_confirmation_id(*args, **kwargs):
        calls.append((args, kwargs))
        return target

    monkeypatch.setattr(cli.confirmations, "respond_to_confirmation_id", respond_to_confirmation_id)


def test_confirmations_refreshes_session_once_on_needauth(monkeypatch, capsys):
    target = Confirmation(
        id="abc",
        nonce="nonce",
        creator_id="creator",
        type_name="Trade",
        headline="Trade offer",
        summary="Summary",
    )
    monkeypatch.setattr(
        cli.storage,
        "load_accounts",
        lambda: {
            STEAMID64: AccountMetadata(
                steamid64=STEAMID64,
                account_name="fixture",
                device_id="android:fixture",
            )
        },
    )
    monkeypatch.setattr(cli.storage, "get_required_secret", lambda steamid64, field: IDENTITY_SECRET)
    monkeypatch.setattr(cli.session, "get_community_session", lambda steamid64: "expired-session")
    refresh_calls = []

    def refresh_community_session(steamid64):
        refresh_calls.append(steamid64)
        return "fresh-session"

    monkeypatch.setattr(cli.session, "refresh_community_session", refresh_community_session)
    confirmation_sessions = []

    def get_confirmations(community_session, *args, **kwargs):
        confirmation_sessions.append(community_session)
        if len(confirmation_sessions) == 1:
            raise cli.confirmations.NeedAuthenticationError("expired")
        return [target]

    monkeypatch.setattr(cli.confirmations, "get_confirmations", get_confirmations)

    assert cli.main(["confirmations", STEAMID64]) == 0

    assert refresh_calls == [STEAMID64]
    assert confirmation_sessions == ["expired-session", "fresh-session"]
    assert "abc\tTrade\tcreator\tTrade offer\tSummary\n" in capsys.readouterr().out


def test_approve_refuses_wrong_confirmation_phrase_without_action(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["approve", STEAMID64, "abc"]) == 1

    output = capsys.readouterr().out
    assert calls == []
    assert f"account: fixture ({STEAMID64})" in output
    assert "Approval cancelled." in output


def test_approve_reports_account_lock(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    message = f"another SteamGuardPC operation is already running for {STEAMID64}"

    @contextmanager
    def account_operation_lock(steamid64):
        raise cli.operation_lock.OperationLockError(message)
        yield

    monkeypatch.setattr(cli.operation_lock, "account_operation_lock", account_operation_lock)

    assert cli.main(["approve", STEAMID64, "abc"]) == 1

    captured = capsys.readouterr()
    assert calls == []
    assert message in captured.err

def test_cancel_requires_exact_cancel_phrase(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("CANCEL abc\n"))

    assert cli.main(["cancel", STEAMID64, "abc"]) == 0

    output = capsys.readouterr().out
    assert len(calls) == 1
    assert calls[0][1]["accept"] is False
    assert f"account: fixture ({STEAMID64})" in output
    assert f"Cancelled abc.\n" in output
