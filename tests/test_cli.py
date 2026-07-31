import io
import json

import pytest

from steamguard_pc import cli
from steamguard_pc.models import AccountMetadata, Confirmation


SHARED_SECRET = "MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
IDENTITY_SECRET = "aWRlbnRpdHktc2VjcmV0LTEyMzQ="
STEAMID64 = "76561197960287930"


def test_code_timestamp_prints_deterministic_code(monkeypatch, capsys):
    monkeypatch.setattr(cli.storage, "get_required_secret", lambda steamid64, field: SHARED_SECRET)

    assert cli.main(["code", STEAMID64, "--timestamp", "0"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "CX2MR expires_in=30s",
        "Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.",
    ]



def test_top_level_help_is_descriptive(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["-h"])

    assert excinfo.value.code == 0
    output = capsys.readouterr().out
    assert "SteamGuardPC is a Windows-focused Steam Guard helper." in output
    assert "Common workflows:" in output
    assert "steamguard-pc setup" in output
    assert "shared_secret" in output
    assert "commands:" in output
    assert "setup" in output
    assert "Guided first-run setup." in output
    assert "Run `steamguard-pc COMMAND -h`" in output

def test_import_mafile_does_not_print_secret_values(monkeypatch, tmp_path, capsys):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(
        json.dumps(
            {
                "steamid": STEAMID64,
                "account_name": "fixture",
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
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
    assert printed == f"Imported fixture ({STEAMID64})\n"
    for secret in [SHARED_SECRET, IDENTITY_SECRET, "secure-cookie", "session-cookie"]:
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
    assert calls[-1] == ("finalize", "access-token", STEAMID64, SHARED_SECRET, "12345")
    output = capsys.readouterr().out
    assert f"Authenticator added and finalized for fixture ({STEAMID64})." in output
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

    def respond_to_confirmation_id(*args, **kwargs):
        calls.append((args, kwargs))
        return target

    monkeypatch.setattr(cli.confirmations, "respond_to_confirmation_id", respond_to_confirmation_id)


def test_approve_refuses_wrong_confirmation_phrase_without_action(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["approve", STEAMID64, "abc"]) == 1

    assert calls == []
    assert "Approval cancelled." in capsys.readouterr().out


def test_cancel_requires_exact_cancel_phrase(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("CANCEL abc\n"))

    assert cli.main(["cancel", STEAMID64, "abc"]) == 0

    assert len(calls) == 1
    assert calls[0][1]["accept"] is False
    assert f"Cancelled abc.\n" in capsys.readouterr().out
