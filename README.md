# steamguard-pc

steamguard-pc is a Windows command-line Steam Guard manager. It can import an existing Steam Desktop Authenticator `.maFile` or enroll a new mobile authenticator, generate Steam's 5-character login codes, approve or cancel mobile confirmations, approve or deny pending login confirmations, and back up local authenticator data.

It is not affiliated with Valve or Steam.

## Requirements

- Windows.
- Python 3.11 or newer.
- A working `keyring` backend. The null backend is rejected; on Windows, `keyring` should use Windows secret storage.
- Network access to Steam for sign-in, enrollment, token refresh, Steam-time sync, recovery-code creation, and confirmations.

## Install

```powershell
python -m pip install .
steamguard-pc --help
```

## Quick start

Run guided setup:

```powershell
steamguard-pc setup
```

Setup offers three paths:

1. Sign in and add a new Steam Guard mobile authenticator.
2. Sign in only, storing the tokens and Steam Community cookies needed by confirmation commands.
3. Import an existing Steam Desktop Authenticator `.maFile`.

If you already have a `.maFile`:

```powershell
steamguard-pc setup --mafile C:\path\to\account.maFile
```

Encrypted SDA files are supported when the matching `manifest.json` is beside the `.maFile`; steamguard-pc prompts for the SDA passkey. If the file contains session tokens or cookies, they are imported without printing them.

After setup:

```powershell
steamguard-pc accounts
steamguard-pc code STEAMID64
steamguard-pc confirmations STEAMID64
```

## Common workflows

### Generate login codes

```powershell
steamguard-pc code STEAMID64
steamguard-pc code STEAMID64 --steam-time
steamguard-pc code STEAMID64 --plain
```

`--steam-time` queries Steam server time before generating the code. Use it when Steam rejects codes from the local clock. `--plain` prints only the 5-character code for copying or scripting.

### Handle mobile confirmations

```powershell
steamguard-pc confirmations STEAMID64
steamguard-pc approve STEAMID64 CONFIRMATION_ID
steamguard-pc cancel  STEAMID64 CONFIRMATION_ID
```

Single-confirmation actions reload the current item, show account and confirmation details, try to show a trade-offer id when available, require an exact typed phrase, submit the action, then verify the item disappeared.

Batch actions are available after review:

```powershell
steamguard-pc approve-all STEAMID64
steamguard-pc cancel-all  STEAMID64
```

`approve-all` is intentionally narrow: it submits only when every displayed item is a Trade or Market listing confirmation. `cancel-all` cancels the displayed batch after exact typed consent.

### Handle Steam login confirmations

```powershell
steamguard-pc login-confirmations STEAMID64
steamguard-pc approve-login STEAMID64 CLIENT_ID
steamguard-pc deny-login    STEAMID64 CLIENT_ID
```

Login-confirmation actions show the pending login's IP, location, platform, and device details before requiring exact typed consent.

### Refresh or store a Steam Community session

Confirmation commands need a valid Steam Community session. Refresh it by signing in:

```powershell
steamguard-pc login ACCOUNT_NAME
```

Or copy cookies manually:

```powershell
steamguard-pc cookie-guide
$env:STEAMGUARD_PC_STEAM_LOGIN_SECURE = "..."
$env:STEAMGUARD_PC_SESSIONID = "..."
steamguard-pc set-cookies STEAMID64
```

Only `steamLoginSecure` and `sessionid` are needed. Treat both like passwords.

### Back up and restore

```powershell
steamguard-pc export-backup C:\private\steamguard.sgbak [STEAMID64 ...]
steamguard-pc import-backup C:\private\steamguard.sgbak
```

Backups contain selected account metadata, authenticator secrets, and session tokens. They use Argon2id key derivation, AES-256-CBC encryption, and HMAC-SHA512 authentication. The passphrase must be at least 16 characters; steamguard-pc cannot recover a lost passphrase.

Revocation codes are excluded by default. Include them only for private offline recovery backups:

```powershell
steamguard-pc export-backup C:\private\steamguard.sgbak --include-revocation-code
```

Use `--force` to overwrite an existing backup. During import, new accounts are added automatically and existing matching accounts prompt before overwrite. Each imported account name and SteamID is printed. Use `import-backup --replace` only to overwrite all matches without per-account prompts.

### Revocation, removal, and recovery codes

```powershell
steamguard-pc revocation-code STEAMID64
steamguard-pc remove-authenticator STEAMID64
steamguard-pc recovery-codes STEAMID64
```

- `revocation-code` reveals the stored Steam `R#####` authenticator-removal code after exact typed consent.
- `remove-authenticator` asks Steam to remove the mobile authenticator with the stored revocation code, then deletes local authenticator secrets while keeping local sign-in/session tokens.
- `recovery-codes` creates one-time Steam backup/recovery codes, prints them once, and does not store them. Steam requires a phone number bound to the account and verifies this action by SMS, not email.

## Command reference

Run `steamguard-pc COMMAND -h` for command-specific options.

| Command | Purpose |
| --- | --- |
| `setup [--mafile PATH] [--skip-cookies]` | Guided setup: enroll, sign in for cookies, or import a `.maFile`. |
| `enroll [ACCOUNT_NAME]` | Sign in, add a mobile authenticator, store its secrets, and finalize with Steam's activation code. |
| `login [ACCOUNT_NAME]` | Sign in and store refresh/access tokens plus Steam Community cookies. |
| `login-confirmations STEAMID64` | List pending Steam login approval requests. |
| `approve-login STEAMID64 CLIENT_ID` | Approve one pending Steam login request after review and exact typed consent. |
| `deny-login STEAMID64 CLIENT_ID` | Deny one pending Steam login request after review and exact typed consent. |
| `accounts [--json] [--delete STEAMID64]` | List local account metadata or delete one local account and its stored secrets. Steam is not changed. |
| `code STEAMID64 [--timestamp UNIX_TIME] [--steam-time] [--plain]` | Print a Steam Guard login code. |
| `confirmations STEAMID64 [--json]` | List pending mobile confirmations. |
| `approve STEAMID64 CONFIRMATION_ID` | Approve one pending mobile confirmation. |
| `cancel STEAMID64 CONFIRMATION_ID` | Cancel one pending mobile confirmation. |
| `approve-all STEAMID64` | Approve all displayed confirmations only when all are Trade or Market listing items. |
| `cancel-all STEAMID64` | Cancel every displayed pending confirmation. |
| `import-mafile PATH` | Import shared/identity secrets and SDA session fields from a `.maFile`. |
| `find-mafiles [DIR ...]` | Search common SDA locations or supplied directories for `.maFile` candidates. |
| `cookie-guide` | Show browser steps for copying Steam Community cookies. |
| `set-cookies STEAMID64` | Store `steamLoginSecure` and `sessionid` from environment variables or hidden prompts. |
| `export-backup PATH [STEAMID64 ...] [--force] [--include-revocation-code]` | Export selected accounts to an encrypted backup. |
| `import-backup PATH [--replace]` | Import accounts from an encrypted steamguard-pc backup; prompts before overwriting matching local accounts unless `--replace` is used. |
| `revocation-code STEAMID64` | Reveal the stored authenticator revocation code. |
| `remove-authenticator STEAMID64` | Remove the Steam mobile authenticator and delete local authenticator secrets. |
| `recovery-codes STEAMID64` | Create and print one-time Steam backup/recovery codes; requires account phone/SMS confirmation. |
| `completion {bash,zsh,powershell}` | Print a shell completion script. |
| `help [COMMAND]` | Show top-level or command-specific help. |

Global options:

| Option | Purpose |
| --- | --- |
| `--version` | Print the package version. |
| `--color {auto,always,never}` | Control ANSI color output. |
| `--no-color` | Disable ANSI color output. |

## Storage and security model

steamguard-pc separates metadata from secrets:

- `%APPDATA%\steamguard-pc\config.json` stores non-secret metadata: SteamID64, account name, generated device id, and import timestamp.
- Windows secret storage stores sensitive fields under service `steamguard-pc`: shared secret, identity secret, revocation code, refresh/access tokens, Steam Community cookies, serial number, token gid, and imported authenticator URI.
- `%APPDATA%\steamguard-pc\locks\` stores per-account lock files used to prevent overlapping destructive or confirmation operations.
- Set `STEAMGUARD_PC_CONFIG_DIR` to move the config and lock directory.

Steam passwords are prompted only for `login`, `enroll`, or guided setup sign-in. Passwords are sent only to Steam over HTTPS and are not stored. The credential login flow is implemented in this project with Steam's authentication service: it fetches Steam's RSA key, encrypts the password client-side, handles supported Steam Guard code or approval challenges, polls for tokens, and stores only resulting tokens/cookies.

Sensitive operations require exact typed consent. The CLI avoids printing secrets except when a command exists to reveal newly created or stored recovery material. Keep `.maFile` files, encrypted backups, cookie values, refresh/access tokens, revocation codes, and recovery codes out of Git, Downloads, cloud-sync folders, logs, screenshots, and issue reports.

## Notes and limits

- Adding or removing a mobile authenticator changes Steam account security state and can affect trade or Community Market holds.
- `accounts --delete STEAMID64` removes only local steamguard-pc metadata and secrets. It does not remove the authenticator from Steam.
- Sign-in supports email codes, mobile authenticator codes, and email/mobile approval prompts. Unsupported Steam risk checks, CAPTCHA, agreements, or extra challenge URLs must be completed outside this tool before retrying.
- If confirmations report an expired session, run `steamguard-pc login ACCOUNT_NAME` or `steamguard-pc set-cookies STEAMID64`.
- If Steam rejects generated login codes, sync Windows time or use `steamguard-pc code STEAMID64 --steam-time`.
- Steam's mobile confirmation endpoints are not a stable public API; endpoint changes can require maintenance.
