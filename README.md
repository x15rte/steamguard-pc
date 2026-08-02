# steamguard-pc

`steamguard-pc` is a Windows CLI for Steam Guard. It can import Steam Desktop Authenticator `.maFile` data, enroll a new mobile authenticator, generate 5-character login codes, review/approve/cancel confirmations, and export encrypted backups.

Not affiliated with Valve or Steam.

## Requirements

- Windows. Secret storage and operation locks are Windows-specific.
- Python 3.11 or newer.
- `uv` to install from the GitHub repository.
- A working non-null `keyring` backend; on Windows this should be Windows secret storage.
- Network access to Steam and access to the account's current sign-in factors for setup, login, enrollment, confirmations, and recovery-code creation.

## Install

```powershell
uv tool install git+https://github.com/x15rte/steamguard-pc.git -p 3.14
steamguard-pc --help
```

If `uv` says its tool bin directory is not on `PATH`:

```powershell
uv tool update-shell
```

## Update

```powershell
uv tool upgrade steamguard-pc
```

## Setup

Guided setup:

```powershell
steamguard-pc setup
```

Setup can:

1. Sign in and add a new Steam Guard mobile authenticator.
2. Sign in only, storing tokens and Steam Community cookies for confirmation commands.
3. Import an existing Steam Desktop Authenticator `.maFile`.

Import a known `.maFile` directly:

```powershell
steamguard-pc setup --mafile C:\path\to\account.maFile
```

Encrypted SDA files are supported when the matching `manifest.json` is beside the `.maFile`; the SDA passkey is prompted. Imported session tokens and cookies are stored when present and are never printed. Use `--skip-cookies` to import authenticator secrets without cookies.

After setup:

```powershell
steamguard-pc accounts
steamguard-pc code STEAMID64
steamguard-pc confirmations STEAMID64
```

## Common workflows

Generate login codes:

```powershell
steamguard-pc code STEAMID64
steamguard-pc code STEAMID64 --steam-time
steamguard-pc code STEAMID64 --plain
```

`--steam-time` queries Steam server time when the local clock may be wrong. `--plain` prints only the 5-character code.

Handle mobile confirmations:

```powershell
steamguard-pc confirmations STEAMID64
steamguard-pc approve STEAMID64 CONFIRMATION_ID
steamguard-pc cancel  STEAMID64 CONFIRMATION_ID
steamguard-pc approve-all STEAMID64
steamguard-pc cancel-all  STEAMID64
```

Single-confirmation actions reload and show the current item, require an exact typed phrase, submit the action, then verify the item disappeared. `approve-all` only submits when every displayed item is a Trade or Market listing confirmation; `cancel-all` cancels the displayed batch after exact typed consent.

Handle Steam login confirmations:

```powershell
steamguard-pc login-confirmations STEAMID64
steamguard-pc approve-login STEAMID64 CLIENT_ID
steamguard-pc deny-login    STEAMID64 CLIENT_ID
```

These commands show IP, location, platform, and device details before exact typed consent.

Refresh or store a Steam Community session:

```powershell
steamguard-pc login ACCOUNT_NAME
steamguard-pc cookie-guide
$env:STEAMGUARD_PC_STEAM_LOGIN_SECURE = "..."
$env:STEAMGUARD_PC_SESSIONID = "..."
steamguard-pc set-cookies STEAMID64
```

Only `steamLoginSecure` and `sessionid` are needed. Treat both like passwords.

Back up and restore:

```powershell
steamguard-pc export-backup C:\private\steamguard.sgbak [STEAMID64 ...]
steamguard-pc import-backup C:\private\steamguard.sgbak
```

Backups include selected account metadata, authenticator secrets, and session tokens. They use Argon2id, AES-256-CBC, and HMAC-SHA512. The passphrase must be at least 16 characters and cannot be recovered. Revocation codes are excluded unless `--include-revocation-code` is passed. Use `--force` to overwrite a backup and `import-backup --replace` to overwrite matching local accounts without per-account prompts.

Recovery and removal:

```powershell
steamguard-pc revocation-code STEAMID64
steamguard-pc remove-authenticator STEAMID64
steamguard-pc recovery-codes STEAMID64
```

`revocation-code` reveals the stored Steam `R#####` authenticator-removal code after exact typed consent. `remove-authenticator` removes the mobile authenticator from Steam and deletes local authenticator secrets while keeping local sign-in/session tokens. `recovery-codes` creates one-time Steam backup codes, prints them once, and does not store them; Steam requires phone/SMS confirmation.

## Command reference

Run `steamguard-pc help COMMAND` or `steamguard-pc COMMAND -h` for details.

| Command | Purpose |
| --- | --- |
| `setup [--mafile PATH] [--skip-cookies]` | Guided setup: enroll, sign in for cookies, or import a `.maFile`. |
| `enroll [ACCOUNT_NAME]` | Sign in, add a mobile authenticator, store secrets, and finalize activation. |
| `login [ACCOUNT_NAME]` | Sign in and store refresh/access tokens plus Steam Community cookies. |
| `login-confirmations STEAMID64` | List pending Steam login approval requests. |
| `approve-login STEAMID64 CLIENT_ID` | Approve one pending login request after review. |
| `deny-login STEAMID64 CLIENT_ID` | Deny one pending login request after review. |
| `import-mafile PATH` | Import shared/identity secrets and SDA session fields from a `.maFile`. |
| `export-backup PATH [STEAMID64 ...] [--force] [--include-revocation-code]` | Export selected accounts to an encrypted backup. |
| `import-backup PATH [--replace]` | Import an encrypted backup; prompts before overwriting matches unless `--replace` is used. |
| `code STEAMID64 [--timestamp UNIX_TIME] [--steam-time] [--plain]` | Print a Steam Guard login code. |
| `confirmations STEAMID64 [--json]` | List pending mobile confirmations. |
| `approve STEAMID64 CONFIRMATION_ID` | Approve one pending mobile confirmation. |
| `cancel STEAMID64 CONFIRMATION_ID` | Cancel one pending mobile confirmation. |
| `approve-all STEAMID64` | Approve all displayed confirmations only when all are Trade or Market listings. |
| `cancel-all STEAMID64` | Cancel every displayed pending confirmation. |
| `revocation-code STEAMID64` | Reveal the stored authenticator revocation code. |
| `remove-authenticator STEAMID64` | Remove the Steam mobile authenticator and delete local authenticator secrets. |
| `recovery-codes STEAMID64` | Create one-time Steam backup codes; requires phone/SMS confirmation. |
| `accounts [--json] [--delete STEAMID64]` | List local account metadata or delete one local account and its stored secrets. |
| `find-mafiles [DIR ...]` | Search common SDA locations or supplied directories for `.maFile` candidates. |
| `cookie-guide` | Show browser steps for copying Steam Community cookies. |
| `set-cookies STEAMID64` | Store `steamLoginSecure` and `sessionid` from environment variables or hidden prompts. |
| `completion {bash,zsh,powershell}` | Print a shell completion script. |
| `help [COMMAND]` | Show top-level or command-specific help. |

Global options: `--version`, `--color {auto,always,never}`, `--no-color`.

## Storage and security

- `%APPDATA%\steamguard-pc\config.json` stores non-secret metadata: SteamID64, account name, generated device ID, and import timestamp.
- Windows secret storage stores sensitive fields under service `steamguard-pc`: shared secret, identity secret, revocation code, refresh/access tokens, Steam Community cookies, serial number, token gid, and imported authenticator URI.
- `%APPDATA%\steamguard-pc\locks\` stores per-account lock files that prevent overlapping destructive or confirmation operations.
- `STEAMGUARD_PC_CONFIG_DIR` moves the config and lock directory.

Steam passwords are prompted only for `setup`, `login`, or `enroll`; they are sent only to Steam over HTTPS and are not stored. Sensitive operations require exact typed consent. Keep `.maFile` files, backups, cookies, tokens, revocation codes, and recovery codes out of Git, cloud-sync folders, logs, screenshots, and issue reports.

## Troubleshooting and limits

- `steamguard-pc` not found: run `uv tool update-shell`, open a new shell, then retry.
- Null or unavailable keyring: fix Windows secret storage before setup.
- Expired confirmation session: run `steamguard-pc login ACCOUNT_NAME` or `steamguard-pc set-cookies STEAMID64`.
- Rejected login codes: sync Windows time or use `steamguard-pc code STEAMID64 --steam-time`.
- CAPTCHA, agreements, risk checks, or unsupported challenge URLs: complete them outside this tool, then retry.
- `accounts --delete STEAMID64` deletes only local data; it does not remove the authenticator from Steam.
- Adding or removing a mobile authenticator changes Steam account security state and can affect trade or Community Market holds.
- Steam mobile confirmation endpoints are not a stable public API and may require maintenance.

## Development

```powershell
python -m pip install -e ".[dev]"
steamguard-pc --help
python -m pytest
```

The pytest suite includes the configured pyright check. CI runs on `windows-latest` with Python 3.11.

## License

MIT. See [LICENSE](LICENSE).
