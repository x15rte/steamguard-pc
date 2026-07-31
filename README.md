# SteamGuardPC

SteamGuardPC stores Steam Guard secrets in Windows secret storage and keeps account-changing actions behind explicit typed consent.

## Quick start

```powershell
py -3.11 -m venv .venv
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

## Commands

| Command | Purpose |
| --- | --- |
| `setup` | Guided first run: enroll, login-only, or `.maFile` import. |
| `enroll [ACCOUNT_NAME]` | Add and finalize a Steam mobile authenticator. |
| `login [ACCOUNT_NAME]` | Sign in or refresh Steam Community session cookies. |
| `import-mafile PATH` | Import a decrypted Steam Desktop Authenticator `.maFile`. |
| `code STEAMID64` | Print the current 5-character Steam Guard code. |
| `confirmations STEAMID64` | List pending mobile confirmations. |
| `approve STEAMID64 ID` | Approve one confirmation after exact typed consent. |
| `cancel STEAMID64 ID` | Cancel one confirmation after exact typed consent. |
| `revocation-code STEAMID64` | Reveal the stored `R#####` revocation code after exact typed consent. |

## Consent phrases

| Action | Required phrase |
| --- | --- |
| Add authenticator | `ADD AUTHENTICATOR <steamid64>` |
| Request activation email | `SEND ACTIVATION EMAIL <steamid64>` |
| Show revocation code | `SHOW REVOCATION CODE <steamid64>` |
| Approve confirmation | `APPROVE <confirmation_id>` |
| Cancel confirmation | `CANCEL <confirmation_id>` |

## Requirements

- Windows-focused.
- Python `>=3.11`.
- Working Python `keyring` backend, normally Windows Credential Manager.
- Steam network access for sign-in, enrollment, confirmations, and session refresh.

Runtime dependencies: `keyring>=25`, `requests>=2.32`.

## Storage

Plain metadata:

```text
%APPDATA%\SteamGuardPC\config.json
```

Secrets in keyring service `SteamGuardPC`:

- `shared_secret`
- `identity_secret`
- `revocation_code`
- `refresh_token`
- `access_token`
- `steamLoginSecure`
- `sessionid`

For isolated runs:

```powershell
$env:STEAMGUARDPC_CONFIG_DIR = "C:\path\to\isolated-config"
```

## Safety

- Treat Steam passwords, session cookies, generated codes, activation codes, and revocation codes as account credentials.
- The `R#####` revocation code can remove the authenticator. Store it offline.
- Keep Windows time synchronized; Steam Guard codes are time based.
- Keep exported `.maFile` files out of Git, Downloads, and cloud-sync folders.
- If keyring is unavailable, fix the keyring backend before storing credentials.

## Development

```powershell
.\.venv\Scripts\python -m pytest
```

Offline crypto smoke:

```powershell
.\.venv\Scripts\python -c "from steamguard_pc.crypto import steam_totp, confirmation_key, generate_device_id; s='MDEyMzQ1Njc4OWFiY2RlZmdoaWo='; i='aWRlbnRpdHktc2VjcmV0LTEyMzQ='; assert steam_totp(s,0)=='CX2MR'; assert confirmation_key(i,'conf',1700000000)==(1700000000,'6eXMXFho61EmjoiIvP/WlyItlCU='); assert generate_device_id('76561197960287930')=='android:6d3f10d9-6369-a1ae-97a0-94df28b95192'; print('offline steamguard smoke ok')"
```
