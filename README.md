# SteamGuardPC

Windows Python CLI for Steam Guard codes, authenticator enrollment, and confirmation handling.

## Quick start

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\steamguard-pc setup
```

Then:

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc code <steamid64>
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

Full command guide: [USAGE.md](USAGE.md).

## Requirements

- Windows-focused.
- Python `>=3.11`.
- Working Python `keyring` backend, normally Windows Credential Manager.
- Steam network access for sign-in, enrollment, confirmations, and session refresh.

Runtime dependencies: `keyring>=25`, `cryptography>=45`, `requests>=2.32`.

## Commands

| Command | Purpose |
| --- | --- |
| `setup` | Guided first run: enroll, login-only, or `.maFile` import. |
| `enroll [ACCOUNT_NAME]` | Add and finalize a Steam mobile authenticator. |
| `login [ACCOUNT_NAME]` | Sign in or refresh Steam Community session cookies. |
| `import-mafile PATH` | Import a decrypted Steam Desktop Authenticator `.maFile`. |
| `export-backup PATH [STEAMID64 ...]` | Write an encrypted SteamGuardPC backup after exact typed consent. |
| `import-backup PATH` | Import an encrypted SteamGuardPC backup after exact typed consent. |
| `code STEAMID64` | Print the current 5-character Steam Guard code. |
| `confirmations STEAMID64` | List pending mobile confirmations. |
| `approve STEAMID64 ID` | Approve one confirmation after exact typed consent. |
| `cancel STEAMID64 ID` | Cancel one confirmation after exact typed consent. |
| `approve-all STEAMID64` | Review and approve every displayed confirmation after exact typed consent. |
| `cancel-all STEAMID64` | Review and cancel every displayed confirmation after exact typed consent. |
| `revocation-code STEAMID64` | Reveal the stored `R#####` revocation code after exact typed consent. |
| `recovery-codes STEAMID64` | Create one-time Steam recovery codes after exact typed consent. |

## Consent phrases

| Action | Required phrase |
| --- | --- |
| Add authenticator | `ADD AUTHENTICATOR <steamid64>` |
| Request activation email | `SEND ACTIVATION EMAIL <steamid64>` |
| Show revocation code | `SHOW REVOCATION CODE <steamid64>` |
| Create recovery codes | `CREATE RECOVERY CODES <steamid64>` |
| Approve confirmation | `APPROVE <confirmation_id>` |
| Cancel confirmation | `CANCEL <confirmation_id>` |
| Approve all confirmations | `APPROVE ALL <count> CONFIRMATIONS <steamid64>` |
| Cancel all confirmations | `CANCEL ALL <count> CONFIRMATIONS <steamid64>` |
| Export encrypted backup | `EXPORT BACKUP <count> ACCOUNTS` |
| Import encrypted backup | `IMPORT BACKUP` |

## Storage

Plain metadata:

```text
%APPDATA%\SteamGuardPC\config.json
```

For isolated metadata:

```powershell
$env:STEAMGUARDPC_CONFIG_DIR = "C:\path\to\isolated-config"
```

Secrets in keyring service `SteamGuardPC`:

- `shared_secret`
- `identity_secret`
- `revocation_code`
- `refresh_token`
- `access_token`
- `steamLoginSecure`
- `sessionid`

Encrypted backups are portable `.sgbak` JSON wrappers using a KeePassXC-style profile: Argon2id key derivation, AES-256-CBC encryption, and HMAC-SHA512 authentication. Store the backup file and passphrase separately; SteamGuardPC cannot recover a lost backup passphrase.
