<div align="center">

# SteamGuardPC

**A careful Windows CLI for Steam Guard codes, authenticator enrollment, and one-at-a-time mobile confirmations.**

[![Steam Guard helper](https://img.shields.io/badge/Steam%20Guard-helper-1b2838?style=for-the-badge&logo=steam&logoColor=white)](#steamguardpc)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Windows focused](https://img.shields.io/badge/Windows-focused-0078D4?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0yIDRsOC0xdjhIMlY0em0xMC0xbDEwLTF2OUgxMlYzek0yIDEzaDh2OGwtOC0xdi03em0xMCAwaDEwdjlsLTEwLTF2LTh6Ii8%2BPC9zdmc%2B)](#requirements)
[![Keyring required](https://img.shields.io/badge/secrets-keyring%20required-2E7D32?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0id2hpdGUiIGQ9Ik02IDEwVjhhNiA2IDAgMCAxIDEyIDB2MmgxYTEgMSAwIDAgMSAxIDF2MTBhMSAxIDAgMCAxLTEgMUg1YTEgMSAwIDAgMS0xLTFWMTFhMSAxIDAgMCAxIDEtMWgxem0yIDBoOFY4YTQgNCAwIDAgMC04IDB2MnoiLz48L3N2Zz4%3D)](#storage-model)
[![Release workflow](https://img.shields.io/github/actions/workflow/status/x15rte/steamguardPC/release.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=release)](https://github.com/x15rte/steamguardPC/actions/workflows/release.yml)

</div>

---

## What it is

SteamGuardPC is a small, security-first command-line app for Steam Guard utilities on a Windows PC, with explicit review before every account-changing action.

It keeps the interaction model deliberately explicit:

| Need | Command | Guardrail |
| --- | --- | --- |
| First-run setup | `steamguard-pc setup` | Choose enrollment, login-only, or `.maFile` import. |
| Add a new authenticator | `steamguard-pc enroll <account_name>` | Requires `ADD AUTHENTICATOR <steamid64>`. |
| Show a login code | `steamguard-pc code <steamid64>` | Prints seconds remaining in the 30-second window. |
| Review confirmations | `steamguard-pc confirmations <steamid64>` | Lists pending mobile confirmations only. |
| Approve or cancel | `steamguard-pc approve/cancel ...` | Acts on one selected confirmation after exact typed consent. |
| Back up recovery material | `steamguard-pc revocation-code <steamid64>` | Requires `SHOW REVOCATION CODE <steamid64>`. |

## Operating boundaries

SteamGuardPC keeps risky actions visible and local.

- Confirmation actions require a selected ID and exact typed consent.
- Secrets stay in keyring-backed secret storage.
- Authenticator enrollment uses Steam's activation-code validation; phone-number management stays outside this tool.
- The interface is a CLI so prompts, targets, and consent phrases stay visible.

## Core features

### Authenticator setup

`enroll` signs in, asks for explicit consent, requests a new Steam mobile authenticator, stores the new secrets before finalization, displays the `R#####` revocation code when Steam returns one, then completes Steam's email/SMS activation-code validation process.

If no activation code arrives, the prompt accepts:

```text
SEND ACTIVATION EMAIL <steamid64>
```

SteamGuardPC then asks Steam to send an activation-code email and prompts again.

### Existing authenticator import

`import-mafile` imports a decrypted Steam Desktop Authenticator-compatible `.maFile`, validates required fields, stores secrets in keyring, and prints only the account label plus SteamID64.

Encrypted or unsupported files are rejected with a clear error.

### Offline login codes

`code` generates Steam's 5-character login code locally from the stored `shared_secret` and prints the remaining seconds:

```text
CX2MR expires_in=30s
Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.
```

### Manual confirmations

`approve` and `cancel` first show the selected confirmation details, then require an exact phrase:

```text
APPROVE <confirmation_id>
CANCEL <confirmation_id>
```

A success message is printed only after Steam accepts the action and a refreshed confirmation list no longer contains the target.

## Requirements

- Windows is the intended platform.
- Python `>=3.11`.
- A working Python `keyring` backend, normally Windows Credential Manager.
- Network access to Steam for `setup`, `login`, `enroll`, `confirmations`, `approve`, and `cancel`.

Runtime dependencies:

- `keyring>=25`
- `requests>=2.32`

Development/test extras:

- `pytest>=8`
- `requests-mock>=1.12`

## Install from this checkout

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\steamguard-pc --help
```

If `py -3.11` is unavailable, use any installed Python `>=3.11`:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

## First run

```powershell
.\.venv\Scripts\steamguard-pc setup
```

Then verify the account and generate a code:

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc code <steamid64>
```

If you enrolled a new authenticator, back up the revocation code immediately in a private terminal:

```powershell
.\.venv\Scripts\steamguard-pc revocation-code <steamid64>
```

For full workflows, command reference, and troubleshooting, use [USAGE.md](USAGE.md).

## Storage model

Plain metadata lives in:

```text
%APPDATA%\SteamGuardPC\config.json
```

Fallback when `%APPDATA%` is unavailable:

```text
%USERPROFILE%\AppData\Roaming\SteamGuardPC\config.json
```

Secrets live in Python `keyring` under service name `SteamGuardPC`.

| Stored in config | Stored in keyring |
| --- | --- |
| account name | `shared_secret` |
| SteamID64 | `identity_secret` |
| device id | `revocation_code` |
| metadata only | `refresh_token` |
| metadata only | `access_token` |
| metadata only | `steamLoginSecure` |
| metadata only | `sessionid` |

For tests or isolated runs:

```powershell
$env:STEAMGUARDPC_CONFIG_DIR = "C:\path\to\isolated-config"
```

## Security model

### Treat every secret like an account credential

Do not paste Steam passwords, authenticator secrets, session tokens, cookies, generated login codes, activation codes, or revocation codes into chat, GitHub issues, logs, screenshots, shell history, or support tickets.

### `keyring` is mandatory

Production code fails closed if secret storage is unavailable. Fix the Windows/Python keyring backend before storing credentials.

### `config.json` is not a backup

Deleting Credential Manager entries can make SteamGuardPC unable to generate codes, refresh sessions, reveal the revocation code, or act on confirmations.

### The revocation code is powerful

Steam's `revocation_code` is `R` followed by five digits. It can remove the authenticator from the account. Store it offline.

### Time matters

Steam Guard codes and confirmation keys depend on time. Keep Windows time synchronized.

### Keep exported `.maFile` files out of risky folders

Avoid storing `.maFile` exports in this repository, `Downloads`, or cloud-sync folders. SteamGuardPC warns about common risky import paths, but it cannot protect files after import.

## Development

Run tests:

```powershell
.\.venv\Scripts\python -m pytest
```

Run the offline crypto smoke:

```powershell
.\.venv\Scripts\python -c "from steamguard_pc.crypto import steam_totp, confirmation_key, generate_device_id; s='MDEyMzQ1Njc4OWFiY2RlZmdoaWo='; i='aWRlbnRpdHktc2VjcmV0LTEyMzQ='; assert steam_totp(s,0)=='CX2MR'; assert confirmation_key(i,'conf',1700000000)==(1700000000,'6eXMXFho61EmjoiIvP/WlyItlCU='); assert generate_device_id('76561197960287930')=='android:6d3f10d9-6369-a1ae-97a0-94df28b95192'; print('offline steamguard smoke ok')"
```
