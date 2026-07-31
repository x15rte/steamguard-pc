# SteamGuardPC

SteamGuardPC is a Windows-focused Python CLI for Steam Guard accounts. It can:

- Sign in to Steam interactively and store a Steam Community session.
- Add and finalize a new mobile authenticator interactively.
- Import an existing decrypted `.maFile`.
- Generate offline 5-character Steam Guard login codes.
- List pending Steam mobile confirmations.
- Approve or cancel one selected confirmation with an explicit typed consent phrase.

The project is intentionally a CLI. It does not run background polling, auto-approve confirmations, or write plaintext secrets to config files.

## Status and risk

This tool handles credentials that can grant access to your Steam account. Use it only for accounts you own and understand the consequences for.

Adding or moving a Steam mobile authenticator changes account security state and can affect Steam trade or market restrictions. Test with a low-value account before relying on it.

## Requirements

- Windows is the intended platform.
- Python `>=3.11`.
- Windows Credential Manager or another `keyring` backend available to Python.
- Network access to Steam for `login`, `enroll`, `confirmations`, `approve`, and `cancel`.

Runtime dependencies are declared in `pyproject.toml`:

- `keyring>=25`
- `requests>=2.32`

Development/test dependencies:

- `pytest>=8`
- `requests-mock>=1.12`

## Installation from this checkout

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

If `py -3.11` is unavailable, use any installed Python version `>=3.11`:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

Run the CLI:

```powershell
.\.venv\Scripts\steamguard-pc --help
```

## Where data is stored

Plain metadata is stored in:

```text
%APPDATA%\SteamGuardPC\config.json
```

If `%APPDATA%` is missing, the fallback is:

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

## Usage

Command workflows, subcommand reference, and troubleshooting live in [USAGE.md](USAGE.md).

## Security considerations

### Treat stored values as account credentials

The following values are sensitive:

- Steam password
- `shared_secret`
- `identity_secret`
- `revocation_code`
- `refresh_token`
- `access_token`
- `steamLoginSecure`
- `sessionid`
- generated Steam Guard codes
- activation codes from email or SMS

Do not paste them into chat, GitHub issues, logs, screenshots, shell history, or support tickets.

### Windows secret storage is mandatory

Production code uses `keyring` and fails closed if secret storage is unavailable. It does not write plaintext fallback JSON files.

If keyring fails, fix the Windows/Python keyring backend. Do not add plaintext storage for convenience.

### Config file is not a backup

`config.json` contains only metadata. Losing Windows Credential Manager entries or deleting keyring secrets can make the app unable to generate codes or confirmations.

If you enroll a new authenticator, make sure you have a safe recovery plan. Steam's `revocation_code` is `R` followed by five digits. It can remove the authenticator from the account. `enroll` displays it before asking for the email/SMS activation code when Steam returns one, does not add or link a phone number, and `steamguard-pc revocation-code <steamid64>` reveals the stored revocation code later after exact typed consent.

Store it offline. Do not paste it into logs, chat, issue reports, or screenshots.

### Authenticator enrollment changes account state

`enroll` calls Steam APIs to add and finalize a mobile authenticator. This can affect trade and market restrictions. Do not run it on a high-value account until you have tested the workflow and understand Steam's hold policies.

### Approval and cancellation are intentionally manual

The app does not auto-approve confirmations. `approve` and `cancel` require:

1. An explicit command.
2. Displaying the selected target.
3. An exact typed consent phrase.
4. A post-action refresh proving the target disappeared.

This prevents accidental approval of unknown trade, market, phone-number, or account-recovery prompts.

### Keep the machine clean

A compromised Windows account can potentially read live process memory, intercept input, use active cookies, or call this tool. Steam Guard secrets on the same computer do not protect against malware on that computer.

### Prefer `login` over copied browser cookies

Manual cookie copying is error-prone and exposes secrets in the browser/devtools workflow. The `login` command obtains session credentials through Steam authentication and stores them directly.

### Clock synchronization matters

Steam Guard login codes and confirmation keys depend on time. Keep Windows time synchronized. If Steam rejects valid-looking codes, sync Windows time and retry.

### Do not commit generated files or secrets

Avoid storing `.maFile` files in this repository, `Downloads`, or cloud-sync folders. The CLI warns about common risky import paths, but it cannot protect files after import.


## Development

Run tests:

```powershell
.\.venv\Scripts\python -m pytest
```

Run the offline crypto smoke:

```powershell
.\.venv\Scripts\python -c "from steamguard_pc.crypto import steam_totp, confirmation_key, generate_device_id; s='MDEyMzQ1Njc4OWFiY2RlZmdoaWo='; i='aWRlbnRpdHktc2VjcmV0LTEyMzQ='; assert steam_totp(s,0)=='CX2MR'; assert confirmation_key(i,'conf',1700000000)==(1700000000,'6eXMXFho61EmjoiIvP/WlyItlCU='); assert generate_device_id('76561197960287930')=='android:6d3f10d9-6369-a1ae-97a0-94df28b95192'; print('offline steamguard smoke ok')"
```
