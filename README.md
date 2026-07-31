# SteamGuardPC

SteamGuardPC is a Windows-focused Python CLI for Steam Guard. It stores Steam authenticator and session secrets in Windows secret storage through Python `keyring`, then uses them to generate login codes and handle mobile confirmations.

It supports:

- Interactive Steam sign-in and session refresh.
- Adding a new mobile authenticator, including Steam's email/SMS activation-code validation step.
- Importing an existing decrypted Steam Desktop Authenticator-compatible `.maFile`.
- Offline 5-character Steam Guard login-code generation.
- Listing pending Steam mobile confirmations.
- Approving or cancelling one selected confirmation after exact typed consent.
- Revealing the stored `R#####` Steam Guard revocation code after exact typed consent.

It intentionally does not auto-approve confirmations, run background polling, store plaintext secret backups, or provide a GUI.

## Requirements

- Windows is the intended platform.
- Python `>=3.11`.
- A working Python `keyring` backend, normally Windows Credential Manager.
- Network access to Steam for `setup`, `login`, `enroll`, `confirmations`, `approve`, and `cancel`.

Runtime dependencies are declared in `pyproject.toml`:

- `keyring>=25`
- `requests>=2.32`

Development/test extras:

- `pytest>=8`
- `requests-mock>=1.12`

## Install from this checkout

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

If `py -3.11` is unavailable, use any installed Python `>=3.11`:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

Check the CLI:

```powershell
.\.venv\Scripts\steamguard-pc --help
```

## Quick start

Run the guided setup:

```powershell
.\.venv\Scripts\steamguard-pc setup
```

Setup can:

1. Sign in and add a new mobile authenticator.
2. Sign in only, to store or refresh Steam Community session cookies.
3. Import an existing decrypted `.maFile`.

After setup:

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc code <steamid64>
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

If you enrolled an authenticator in this app, back up the revocation code immediately:

```powershell
.\.venv\Scripts\steamguard-pc revocation-code <steamid64>
```

The usage guide has command workflows and troubleshooting: [USAGE.md](USAGE.md).

## Storage model

Plain account metadata is stored in:

```text
%APPDATA%\SteamGuardPC\config.json
```

If `%APPDATA%` is unavailable, the fallback is:

```text
%USERPROFILE%\AppData\Roaming\SteamGuardPC\config.json
```

For tests or isolated runs, override the config directory:

```powershell
$env:STEAMGUARDPC_CONFIG_DIR = "C:\path\to\isolated-config"
```

Secrets are stored through Python `keyring` under service name `SteamGuardPC`. The config file must not contain:

- `shared_secret`
- `identity_secret`
- `revocation_code`
- `refresh_token`
- `access_token`
- `steamLoginSecure`
- `sessionid`

## Security notes

### Treat stored values as account credentials

The Steam password, authenticator secrets, session tokens, cookies, generated login codes, activation codes, and revocation code are sensitive. Do not paste them into chat, GitHub issues, logs, screenshots, shell history, or support tickets.

### Secret storage is mandatory

Production code fails closed if `keyring` is unavailable. It does not write plaintext fallback JSON files. If keyring fails, fix the Windows/Python keyring backend instead of adding plaintext storage.

### `config.json` is not a backup

`config.json` contains metadata only. Losing Windows Credential Manager entries or deleting keyring secrets can make SteamGuardPC unable to generate codes, refresh sessions, reveal the revocation code, or act on confirmations.

### Enrolling an authenticator changes account state

`enroll` calls Steam APIs to add and finalize a mobile authenticator. It stores the new secrets before finalization, displays the `R#####` revocation code if Steam returns one, and then asks for Steam's activation code from email or SMS. The CLI does not add or link a phone number.

Test enrollment on a low-value account before relying on it for accounts with valuable inventory or market activity.

### The revocation code can remove the authenticator

Steam's `revocation_code` is `R` followed by five digits. Store it offline. `steamguard-pc revocation-code <steamid64>` prints it only after the exact phrase `SHOW REVOCATION CODE <steamid64>`.

### Confirmation actions are intentionally manual

`approve` and `cancel` act on one confirmation at a time. Each command prints the selected confirmation, requires an exact consent phrase, sends one Steam request, then refreshes the list and reports success only after the target disappears.

### Keep Windows time synchronized

Steam Guard login codes and confirmation keys are time based. If Steam rejects valid-looking codes, sync Windows time and generate a fresh code near the start of its 30-second window.

### Keep `.maFile` exports out of unsafe locations

Do not keep `.maFile` files in this repository, `Downloads`, or cloud-sync folders. SteamGuardPC warns about common risky import paths, but it cannot protect files after import.

## Development

Run tests:

```powershell
.\.venv\Scripts\python -m pytest
```

Run the offline crypto smoke:

```powershell
.\.venv\Scripts\python -c "from steamguard_pc.crypto import steam_totp, confirmation_key, generate_device_id; s='MDEyMzQ1Njc4OWFiY2RlZmdoaWo='; i='aWRlbnRpdHktc2VjcmV0LTEyMzQ='; assert steam_totp(s,0)=='CX2MR'; assert confirmation_key(i,'conf',1700000000)==(1700000000,'6eXMXFho61EmjoiIvP/WlyItlCU='); assert generate_device_id('76561197960287930')=='android:6d3f10d9-6369-a1ae-97a0-94df28b95192'; print('offline steamguard smoke ok')"
```
