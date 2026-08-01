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
SDA_PASSKEY = "correct horse battery staple"
SDA_SALT = "MTIzNDU2Nzg="
SDA_IV = "MTIzNDU2Nzg5MGFiY2RlZg=="
SDA_CIPHERTEXT = "q4/CnhwdcdRzn7l4L80qTkpyQEAgef8g09baxLG10KMPcav12ZNzruJneluSEKCCHlnyK/ju/J4kvtqeKCSrSc29SFc4pBlOXdJWxxZL8Vi6pm0abP6DlSpGTuHJAbKtVVP2iYCJvx9icvJw7tEnA1EpQiUIPHdn9yEQkU6CAgta3XdpBLl+vR3EfxeG9YGlOGZJzjnVKlfgzRRcRw660RUGT2s+pLMqQFa4ovB/szbqstAHnLKDVaRmnQXUCH6wwZovLYaflUoec+g1GGWOmBGKdANBedpz1xUUqP0SXeaucrYoLVb3LWat/HYEvGyzOiv+Hv8cMhEj0IK75MQ44w=="


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
    assert "SteamGuardPC manages Steam Guard accounts from a local Windows terminal." not in output
    assert "Authenticator secrets stay in Windows secret storage" not in output
    assert "Quick paths:" in output
    assert "revocation-code" in output
    assert "remove-authenticator" in output
    assert "login-confirmations" in output
    assert "approve-login" in output
    assert "deny-login" in output
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



def test_remove_authenticator_requires_exact_phrase(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture"))
    cli.storage.put_secret(STEAMID64, "revocation_code", REVOCATION_CODE)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected Steam removal path")

    monkeypatch.setattr(cli.storage, "get_required_secret", forbidden)
    monkeypatch.setattr(cli.session, "refresh_auth_tokens", forbidden)
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", forbidden)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["remove-authenticator", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert "Authenticator removal cancelled." in output
    assert REVOCATION_CODE not in output


def test_remove_authenticator_calls_steam_then_deletes_local_authenticator_secrets(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture", device_id="android:fixture"))
    seeded_fields = {
        "shared_secret": SHARED_SECRET,
        "identity_secret": IDENTITY_SECRET,
        "revocation_code": REVOCATION_CODE,
        "serial_number": "serial-1",
        "token_gid": "token-gid-1",
        "uri": "otpauth://totp/steam?secret=fixture",
        "refresh_token": "refresh-token",
        "access_token": "access-token",
        "access_token_obtained_at": "1700000000",
        "steamLoginSecure": "secure-cookie",
        "sessionid": "session-cookie",
    }
    for field, value in seeded_fields.items():
        cli.storage.put_secret(STEAMID64, field, value)

    refresh_calls = []
    remove_calls = []

    def refresh_auth_tokens(steamid64):
        refresh_calls.append(steamid64)
        return "access-token", "refresh-token"

    class FakeEnrollmentClient:
        def remove_authenticator(self, access_token, revocation_code):
            remove_calls.append((access_token, revocation_code))
            assert cli.storage.get_secret(STEAMID64, "shared_secret") == SHARED_SECRET

    monkeypatch.setattr(cli.session, "refresh_auth_tokens", refresh_auth_tokens)
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FakeEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"REMOVE AUTHENTICATOR {STEAMID64}\n"))

    assert cli.main(["remove-authenticator", STEAMID64]) == 0

    assert refresh_calls == [STEAMID64]
    assert remove_calls == [("access-token", REVOCATION_CODE)]
    for field in ("shared_secret", "identity_secret", "revocation_code", "serial_number", "token_gid", "uri"):
        assert cli.storage.get_secret(STEAMID64, field) is None
    for field in ("refresh_token", "access_token", "access_token_obtained_at", "steamLoginSecure", "sessionid"):
        assert cli.storage.get_secret(STEAMID64, field) == seeded_fields[field]
    metadata = cli.storage.load_accounts()[STEAMID64]
    assert metadata.device_id == "android:fixture"

    output = capsys.readouterr().out
    assert "blocks trading or Community Market selling for 15 days" in output
    assert f"Removed Steam Guard mobile authenticator from fixture ({STEAMID64})." in output
    assert REVOCATION_CODE not in output
    assert SHARED_SECRET not in output
    assert IDENTITY_SECRET not in output


def test_remove_authenticator_missing_revocation_code_does_not_refresh_or_cleanup(monkeypatch, keyring_store, capsys):
    cli.storage.upsert_account(AccountMetadata(steamid64=STEAMID64, account_name="fixture", device_id="android:fixture"))
    cli.storage.put_secret(STEAMID64, "shared_secret", SHARED_SECRET)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected Steam removal path")

    monkeypatch.setattr(cli.session, "refresh_auth_tokens", forbidden)
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", forbidden)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"REMOVE AUTHENTICATOR {STEAMID64}\n"))

    assert cli.main(["remove-authenticator", STEAMID64]) == 1

    captured = capsys.readouterr()
    assert f"missing revocation_code for {STEAMID64}" in captured.err
    assert cli.storage.get_secret(STEAMID64, "shared_secret") == SHARED_SECRET

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



def write_encrypted_sda_cli_fixture(tmp_path):
    mafiles_dir = tmp_path / "maFiles"
    mafiles_dir.mkdir()
    mafile_path = mafiles_dir / "account.maFile"
    mafile_path.write_text(SDA_CIPHERTEXT, encoding="utf-8")
    (mafiles_dir / "manifest.json").write_text(
        json.dumps(
            {
                "encrypted": True,
                "entries": [
                    {
                        "filename": "account.maFile",
                        "steamid": 76561197960287930,
                        "encryption_salt": SDA_SALT,
                        "encryption_iv": SDA_IV,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return mafile_path


def test_import_encrypted_sda_mafile_prompts_passkey_without_printing_secrets(monkeypatch, tmp_path, capsys):
    mafile_path = write_encrypted_sda_cli_fixture(tmp_path)

    def getpass(prompt):
        assert prompt == "SDA encryption passkey: "
        return SDA_PASSKEY

    def store_imported_guard(imported):
        assert imported.steamid64 == STEAMID64
        assert imported.account_name == "fixture"
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

    monkeypatch.setattr(cli.getpass, "getpass", getpass)
    monkeypatch.setattr(cli.storage, "store_imported_guard", store_imported_guard)

    assert cli.main(["import-mafile", str(mafile_path)]) == 0

    output = capsys.readouterr().out
    assert f"Imported fixture ({STEAMID64})" in output
    for secret in [
        SDA_PASSKEY,
        SDA_CIPHERTEXT,
        "shared_secret",
        "identity_secret",
        REVOCATION_CODE,
        "secure-cookie",
        "session-cookie",
    ]:
        assert secret not in output

def _seed_cli_backup_account():
    metadata = AccountMetadata(
        steamid64=STEAMID64,
        account_name="fixture",
        device_id="android:fixture",
        last_imported_at="2026-07-31T00:00:00Z",
    )
    cli.storage.upsert_account(metadata)
    cli.storage.put_secret(STEAMID64, "shared_secret", SHARED_SECRET)
    cli.storage.put_secret(STEAMID64, "identity_secret", IDENTITY_SECRET)
    cli.storage.put_secret(STEAMID64, "revocation_code", REVOCATION_CODE)
    return metadata


def test_accounts_delete_requires_exact_phrase_without_removing(monkeypatch, keyring_store, capsys):
    _seed_cli_backup_account()
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["accounts", "--delete", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert f"Delete stored account fixture ({STEAMID64})?" in output
    assert "Account deletion cancelled." in output
    assert STEAMID64 in cli.storage.load_accounts()
    assert cli.storage.get_secret(STEAMID64, "shared_secret") == SHARED_SECRET


def test_accounts_delete_removes_account_without_printing_secrets(monkeypatch, keyring_store, capsys):
    _seed_cli_backup_account()
    monkeypatch.setattr("sys.stdin", io.StringIO(f"DELETE ACCOUNT {STEAMID64}\n"))

    assert cli.main(["accounts", "--delete", STEAMID64]) == 0

    output = capsys.readouterr().out
    assert f"Deleted account fixture ({STEAMID64})." in output
    assert STEAMID64 not in cli.storage.load_accounts()
    assert cli.storage.get_secret(STEAMID64, "shared_secret") is None
    assert cli.storage.get_secret(STEAMID64, "identity_secret") is None
    assert cli.storage.get_secret(STEAMID64, "revocation_code") is None
    for secret in [SHARED_SECRET, IDENTITY_SECRET, REVOCATION_CODE]:
        assert secret not in output


def test_export_backup_requires_exact_phrase(monkeypatch, tmp_path, keyring_store, capsys):
    _seed_cli_backup_account()

    def export_accounts(*args, **kwargs):
        raise AssertionError("export should not run")

    monkeypatch.setattr(cli.backup, "export_accounts", export_accounts)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["export-backup", str(tmp_path / "steamguard.sgbak")]) == 1

    output = capsys.readouterr().out
    assert "Backup export cancelled." in output
    for secret in [SHARED_SECRET, IDENTITY_SECRET, REVOCATION_CODE]:
        assert secret not in output


def test_export_backup_writes_encrypted_file_without_printing_secrets(monkeypatch, tmp_path, keyring_store, capsys):
    _seed_cli_backup_account()
    path = tmp_path / "steamguard.sgbak"
    passphrase = "correct horse battery staple"
    monkeypatch.setattr(cli.backup, "KDF_MEMORY_COST", 8 * cli.backup.KDF_LANES)
    monkeypatch.setattr(cli.backup, "KDF_ITERATIONS", 1)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: passphrase)
    monkeypatch.setattr("sys.stdin", io.StringIO("EXPORT BACKUP 1 ACCOUNTS\n"))

    assert cli.main(["export-backup", str(path)]) == 0

    raw_text = path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert path.exists()
    assert "Wrote encrypted backup for 1 account(s)" in output
    for secret in [SHARED_SECRET, IDENTITY_SECRET, REVOCATION_CODE]:
        assert secret not in raw_text
        assert secret not in output
    assert passphrase not in output


def test_export_backup_include_revocation_code_requires_extra_phrase(monkeypatch, tmp_path, keyring_store, capsys):
    _seed_cli_backup_account()

    def export_accounts(*args, **kwargs):
        raise AssertionError("export should not run")

    monkeypatch.setattr(cli.backup, "export_accounts", export_accounts)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["export-backup", str(tmp_path / "steamguard.sgbak"), "--include-revocation-code"]) == 1

    output = capsys.readouterr().out
    assert "Warning: this backup will include Steam Guard revocation codes." in output
    assert "Backup export cancelled." in output
    assert REVOCATION_CODE not in output


def test_export_backup_include_revocation_code_passes_opt_in(monkeypatch, tmp_path, keyring_store, capsys):
    _seed_cli_backup_account()
    path = tmp_path / "steamguard.sgbak"
    passphrase = "correct horse battery staple"
    calls = []

    def export_accounts(*args, **kwargs):
        calls.append((args, kwargs))
        return 1

    monkeypatch.setattr(cli.backup, "export_accounts", export_accounts)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: passphrase)
    monkeypatch.setattr("sys.stdin", io.StringIO("INCLUDE REVOCATION CODES 1 ACCOUNTS\nEXPORT BACKUP 1 ACCOUNTS\n"))

    assert cli.main(["export-backup", str(path), "--include-revocation-code"]) == 0

    output = capsys.readouterr().out
    assert calls[0][1]["include_revocation_code"] is True
    assert "Wrote encrypted backup for 1 account(s)" in output
    assert REVOCATION_CODE not in output


def test_import_backup_restores_from_cli(monkeypatch, tmp_path, keyring_store, capsys):
    metadata = _seed_cli_backup_account()
    path = tmp_path / "steamguard.sgbak"
    passphrase = "correct horse battery staple"
    monkeypatch.setattr(cli.backup, "KDF_MEMORY_COST", 8 * cli.backup.KDF_LANES)
    monkeypatch.setattr(cli.backup, "KDF_ITERATIONS", 1)
    cli.backup.export_accounts(path, passphrase)
    keyring_store.clear()
    cli.storage.save_accounts({})
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: passphrase)
    monkeypatch.setattr("sys.stdin", io.StringIO("IMPORT BACKUP\n"))

    assert cli.main(["import-backup", str(path)]) == 0

    output = capsys.readouterr().out
    assert "Imported encrypted backup for 1 account(s)." in output
    assert cli.storage.load_accounts()[STEAMID64] == metadata
    assert cli.storage.get_secret(STEAMID64, "shared_secret") == SHARED_SECRET
    assert cli.storage.get_secret(STEAMID64, "identity_secret") == IDENTITY_SECRET
    assert cli.storage.get_secret(STEAMID64, "revocation_code") is None
    for secret in [SHARED_SECRET, IDENTITY_SECRET, REVOCATION_CODE, passphrase]:
        assert secret not in output


def test_import_backup_refuses_wrong_phrase(monkeypatch, tmp_path, capsys):
    def import_accounts(*args, **kwargs):
        raise AssertionError("import should not run")

    monkeypatch.setattr(cli.backup, "import_accounts", import_accounts)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["import-backup", str(tmp_path / "steamguard.sgbak")]) == 1

    assert "Backup import cancelled." in capsys.readouterr().out

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

def test_setup_uses_sda_session_tokens_as_imported_cookies(monkeypatch, tmp_path, capsys):
    mafile_path = tmp_path / "account.maFile"
    mafile_path.write_text(
        json.dumps(
            {
                "account_name": "fixture",
                "shared_secret": SHARED_SECRET,
                "identity_secret": IDENTITY_SECRET,
                "Session": {
                    "SteamID": int(STEAMID64),
                    "AccessToken": "access-token",
                    "RefreshToken": "refresh-token",
                    "SessionID": "session-cookie",
                },
            }
        ),
        encoding="utf-8",
    )

    def store_imported_guard(imported):
        assert imported.steam_login_secure == f"{STEAMID64}%7C%7Caccess-token"
        assert imported.sessionid == "session-cookie"
        return AccountMetadata(
            steamid64=imported.steamid64,
            account_name=imported.account_name,
            device_id=imported.device_id,
            last_imported_at="2026-07-31T00:00:00Z",
        )

    monkeypatch.setattr(cli.storage, "store_imported_guard", store_imported_guard)

    assert cli.main(["setup", "--mafile", str(mafile_path)]) == 0

    output = capsys.readouterr().out
    assert "Steam Community cookies were imported from the .maFile." in output
    assert "access-token" not in output
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
        def add_authenticator(self, access_token, steamid64, account_name=None, device_id=None, sms_phone_id=None):
            calls.append(("add", access_token, steamid64, account_name, device_id, sms_phone_id))
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

        def finalize_authenticator(self, access_token, steamid64, shared_secret, activation_code, validate_sms_code=True):
            calls.append(("finalize", access_token, steamid64, shared_secret, activation_code, validate_sms_code))


    monkeypatch.setattr(cli, "_login_and_store", lambda account_name: (result, metadata))
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FakeEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"ADD AUTHENTICATOR {STEAMID64}\nn\n12345\n"))

    assert cli.main(["enroll", "fixture"]) == 0

    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:shared_secret")] == SHARED_SECRET
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:identity_secret")] == IDENTITY_SECRET
    assert keyring_store[(cli.storage.SERVICE, f"{STEAMID64}:revocation_code")] == REVOCATION_CODE
    assert calls[0] == ("add", "access-token", STEAMID64, "fixture", "android:fixture", None)
    assert calls[-1] == ("finalize", "access-token", STEAMID64, SHARED_SECRET, "12345", False)
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



def test_enroll_command_uses_sms_phone_id_when_phone_is_linked(monkeypatch, keyring_store):
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
        def add_authenticator(self, access_token, steamid64, account_name=None, device_id=None, sms_phone_id=None):
            calls.append(("add", access_token, steamid64, account_name, device_id, sms_phone_id))
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

        def finalize_authenticator(self, access_token, steamid64, shared_secret, activation_code, validate_sms_code=True):
            calls.append(("finalize", access_token, steamid64, shared_secret, activation_code, validate_sms_code))

    monkeypatch.setattr(cli, "_login_and_store", lambda account_name: (result, metadata))
    monkeypatch.setattr(cli.enrollment, "EnrollmentClient", FakeEnrollmentClient)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"ADD AUTHENTICATOR {STEAMID64}\ny\n12345\n"))

    assert cli.main(["enroll", "fixture"]) == 0

    assert calls[0] == ("add", "access-token", STEAMID64, "fixture", "android:fixture", "1")
    assert calls[-1] == ("finalize", "access-token", STEAMID64, SHARED_SECRET, "12345", True)

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


def _seed_login_confirmation_account() -> None:
    cli.storage.upsert_account(
        AccountMetadata(
            steamid64=STEAMID64,
            account_name="fixture",
            device_id="android:fixture",
        )
    )
    cli.storage.put_secret(STEAMID64, "shared_secret", SHARED_SECRET)
    cli.storage.put_secret(STEAMID64, "refresh_token", "refresh-token")


def _patch_login_confirmation_context(monkeypatch, fake_client) -> None:
    def refresh_auth_tokens(steamid64):
        assert steamid64 == STEAMID64
        return "access-token", "refresh-token"

    @contextmanager
    def account_operation_lock(steamid64):
        assert steamid64 == STEAMID64
        yield

    monkeypatch.setattr(cli.session, "refresh_auth_tokens", refresh_auth_tokens)
    monkeypatch.setattr(cli.auth, "SteamAuthClient", lambda: fake_client)
    monkeypatch.setattr(cli.operation_lock, "account_operation_lock", account_operation_lock)


def test_login_confirmations_lists_details(monkeypatch, keyring_store, capsys):
    _seed_login_confirmation_account()
    calls = []

    class FakeClient:
        def get_login_confirmations(self, access_token):
            calls.append(access_token)
            return [
                cli.auth.LoginConfirmation(
                    client_id=123,
                    version=2,
                    ip="203.0.113.10",
                    city="Seattle",
                    state="WA",
                    country="US",
                    platform_type=2,
                    device_friendly_name="Firefox on Windows",
                )
            ]

    _patch_login_confirmation_context(monkeypatch, FakeClient())

    assert cli.main(["login-confirmations", STEAMID64]) == 0

    assert calls == ["access-token"]
    assert capsys.readouterr().out == "123\t203.0.113.10\tSeattle, WA, US\tWeb browser\tFirefox on Windows\n"


def test_login_confirmations_no_pending(monkeypatch, keyring_store, capsys):
    _seed_login_confirmation_account()

    class FakeClient:
        def get_login_confirmations(self, access_token):
            assert access_token == "access-token"
            return []

    _patch_login_confirmation_context(monkeypatch, FakeClient())

    assert cli.main(["login-confirmations", STEAMID64]) == 0

    assert capsys.readouterr().out == "No pending login confirmations.\n"


def test_approve_login_requires_exact_phrase_without_action(monkeypatch, keyring_store, capsys):
    _seed_login_confirmation_account()
    respond_calls = []

    class FakeClient:
        def get_login_confirmation(self, access_token, client_id):
            assert access_token == "access-token"
            assert client_id == 123
            return cli.auth.LoginConfirmation(
                client_id=123,
                version=2,
                ip="203.0.113.10",
                city="Seattle",
                state="WA",
                country="US",
                platform_type=2,
                device_friendly_name="Firefox on Windows",
            )

        def respond_to_login_confirmation(self, *args, **kwargs):
            respond_calls.append((args, kwargs))

    _patch_login_confirmation_context(monkeypatch, FakeClient())
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["approve-login", STEAMID64, "123"]) == 1

    output = capsys.readouterr().out
    assert respond_calls == []
    assert f"account: fixture ({STEAMID64})" in output
    assert "client_id: 123" in output
    assert "Login approval cancelled." in output


def test_approve_login_shows_details_and_submits(monkeypatch, keyring_store, capsys):
    _seed_login_confirmation_account()
    respond_calls = []

    class FakeClient:
        def get_login_confirmation(self, access_token, client_id):
            assert access_token == "access-token"
            return cli.auth.LoginConfirmation(client_id=client_id, version=2, ip="203.0.113.10")

        def respond_to_login_confirmation(self, access_token, steamid64, shared_secret, confirmation, *, confirm):
            respond_calls.append(
                {
                    "access_token": access_token,
                    "steamid64": steamid64,
                    "shared_secret": shared_secret,
                    "client_id": confirmation.client_id,
                    "confirm": confirm,
                }
            )

    _patch_login_confirmation_context(monkeypatch, FakeClient())
    monkeypatch.setattr("sys.stdin", io.StringIO("APPROVE LOGIN 123\n"))

    assert cli.main(["approve-login", STEAMID64, "123"]) == 0

    assert respond_calls == [
        {
            "access_token": "access-token",
            "steamid64": STEAMID64,
            "shared_secret": SHARED_SECRET,
            "client_id": 123,
            "confirm": True,
        }
    ]
    output = capsys.readouterr().out
    assert "ip: 203.0.113.10" in output
    assert "Approved login 123." in output


def test_deny_login_shows_details_and_submits(monkeypatch, keyring_store, capsys):
    _seed_login_confirmation_account()
    respond_calls = []

    class FakeClient:
        def get_login_confirmation(self, access_token, client_id):
            assert access_token == "access-token"
            return cli.auth.LoginConfirmation(client_id=client_id, version=2, ip="203.0.113.10")

        def respond_to_login_confirmation(self, access_token, steamid64, shared_secret, confirmation, *, confirm):
            respond_calls.append(
                {
                    "access_token": access_token,
                    "steamid64": steamid64,
                    "shared_secret": shared_secret,
                    "client_id": confirmation.client_id,
                    "confirm": confirm,
                }
            )

    _patch_login_confirmation_context(monkeypatch, FakeClient())
    monkeypatch.setattr("sys.stdin", io.StringIO("DENY LOGIN 123\n"))

    assert cli.main(["deny-login", STEAMID64, "123"]) == 0

    assert respond_calls == [
        {
            "access_token": "access-token",
            "steamid64": STEAMID64,
            "shared_secret": SHARED_SECRET,
            "client_id": 123,
            "confirm": False,
        }
    ]
    output = capsys.readouterr().out
    assert "ip: 203.0.113.10" in output
    assert "Denied login 123." in output


def _patch_batch_confirmation_context(monkeypatch, calls, current=None):
    confirmations = current if current is not None else [
        Confirmation(
            id="abc",
            nonce="nonce-abc",
            creator_id="creator-abc",
            type_name="Trade",
            headline="Trade offer",
            summary="First summary",
        ),
        Confirmation(
            id="def",
            nonce="nonce-def",
            creator_id="creator-def",
            type_name="Market listing",
            headline="Market sale",
            summary="Second summary",
        ),
    ]
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
    monkeypatch.setattr(cli.session, "get_community_session", lambda steamid64: "community-session")
    monkeypatch.setattr(cli.confirmations, "get_confirmations", lambda *args, **kwargs: list(confirmations))
    monkeypatch.setattr(
        cli.confirmations,
        "get_confirmation_details_html",
        lambda *args, **kwargs: '<div id="tradeoffer_123456"></div>',
    )

    @contextmanager
    def account_operation_lock(steamid64):
        yield

    monkeypatch.setattr(cli.operation_lock, "account_operation_lock", account_operation_lock)

    def respond_to_confirmation_ids(community_session, steamid64, device_id, identity_secret, confirmation_ids, *, accept):
        calls.append(
            {
                "community_session": community_session,
                "steamid64": steamid64,
                "device_id": device_id,
                "identity_secret": identity_secret,
                "ids": list(confirmation_ids),
                "accept": accept,
            }
        )
        return [item for item in confirmations if item.id in confirmation_ids]

    monkeypatch.setattr(cli.confirmations, "respond_to_confirmation_ids", respond_to_confirmation_ids)
    return confirmations


def test_approve_all_requires_exact_phrase_without_action(monkeypatch, capsys):
    calls = []
    _patch_batch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["approve-all", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert calls == []
    assert f"Pending confirmations for fixture ({STEAMID64}): 2" in output
    assert "abc" in output
    assert "def" in output
    assert "Batch approval cancelled." in output


def test_approve_all_reviews_and_submits_displayed_ids(monkeypatch, capsys):
    calls = []
    _patch_batch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"APPROVE ALL 2 CONFIRMATIONS {STEAMID64}\n"))

    assert cli.main(["approve-all", STEAMID64]) == 0

    output = capsys.readouterr().out
    assert calls[0]["ids"] == ["abc", "def"]
    assert calls[0]["accept"] is True
    assert "--- confirmation 1 of 2 ---" in output
    assert "--- confirmation 2 of 2 ---" in output
    assert "trade_offer_id: 123456" in output
    assert "Approved 2 confirmations." in output


def test_cancel_all_reviews_and_submits_displayed_ids(monkeypatch, capsys):
    calls = []
    _patch_batch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"CANCEL ALL 2 CONFIRMATIONS {STEAMID64}\n"))

    assert cli.main(["cancel-all", STEAMID64]) == 0

    output = capsys.readouterr().out
    assert calls[0]["ids"] == ["abc", "def"]
    assert calls[0]["accept"] is False
    assert "--- confirmation 1 of 2 ---" in output
    assert "--- confirmation 2 of 2 ---" in output
    assert "Cancelled 2 confirmations." in output


def test_approve_all_blocks_unknown_confirmation_types(monkeypatch, capsys):
    calls = []
    current = [
        Confirmation(
            id="abc",
            nonce="nonce-abc",
            creator_id="creator-abc",
            type_name="Trade",
            headline="Trade offer",
            summary="First summary",
        ),
        Confirmation(
            id="ghi",
            nonce="nonce-ghi",
            creator_id="creator-ghi",
            type_name="Phone number change",
            headline="Change phone",
            summary="Unknown",
        ),
    ]
    _patch_batch_confirmation_context(monkeypatch, calls, current=current)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    assert cli.main(["approve-all", STEAMID64]) == 1

    output = capsys.readouterr().out
    assert calls == []
    assert "Batch approval blocked: approve-all only supports Trade and Market listing confirmations." in output
    assert "blocked: ghi\tPhone number change\tcreator-ghi" in output


def test_cancel_all_allows_unknown_confirmation_types(monkeypatch, capsys):
    calls = []
    current = [
        Confirmation(
            id="abc",
            nonce="nonce-abc",
            creator_id="creator-abc",
            type_name="Trade",
            headline="Trade offer",
            summary="First summary",
        ),
        Confirmation(
            id="ghi",
            nonce="nonce-ghi",
            creator_id="creator-ghi",
            type_name="Phone number change",
            headline="Change phone",
            summary="Unknown",
        ),
    ]
    _patch_batch_confirmation_context(monkeypatch, calls, current=current)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"CANCEL ALL 2 CONFIRMATIONS {STEAMID64}\n"))

    assert cli.main(["cancel-all", STEAMID64]) == 0

    assert calls[0]["ids"] == ["abc", "ghi"]
    assert calls[0]["accept"] is False


def test_approve_all_allows_numeric_trade_and_market_types(monkeypatch, capsys):
    calls = []
    current = [
        Confirmation(id="abc", nonce="nonce-abc", creator_id="creator-abc", type=2, type_name=None),
        Confirmation(id="def", nonce="nonce-def", creator_id="creator-def", type=3, type_name=None),
    ]
    _patch_batch_confirmation_context(monkeypatch, calls, current=current)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"APPROVE ALL 2 CONFIRMATIONS {STEAMID64}\n"))

    assert cli.main(["approve-all", STEAMID64]) == 0

    assert calls[0]["ids"] == ["abc", "def"]
    assert calls[0]["accept"] is True


def test_approve_all_no_pending_confirmations(monkeypatch, capsys):
    calls = []
    _patch_batch_confirmation_context(monkeypatch, calls, current=[])

    assert cli.main(["approve-all", STEAMID64]) == 0

    assert capsys.readouterr().out == "No pending confirmations.\n"
    assert calls == []

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


def test_cancel_refuses_wrong_confirmation_phrase_without_action(monkeypatch, capsys):
    calls = []
    _patch_confirmation_context(monkeypatch, calls)
    monkeypatch.setattr("sys.stdin", io.StringIO("WRONG\n"))

    assert cli.main(["cancel", STEAMID64, "abc"]) == 1

    output = capsys.readouterr().out
    assert calls == []
    assert f"account: fixture ({STEAMID64})" in output
    assert "Cancellation cancelled." in output


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
