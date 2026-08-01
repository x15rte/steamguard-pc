# SteamGuardPC

SteamGuardPC is a Windows command-line tool for managing Steam Guard on a PC. It can import an existing Steam Desktop Authenticator `.maFile` or enroll a new mobile authenticator, remove a stored mobile authenticator from Steam, generate 5-character Steam Guard login codes, approve or deny Steam login confirmations, and list or act on Steam mobile confirmations.

It is not affiliated with Valve or Steam.

## Requirements

- Windows.
- Python 3.11 or newer.
- A working `keyring` backend. On Windows this should use Windows secret storage; the null backend is rejected.
- Network access to Steam when signing in, enrolling, removing authenticators, refreshing sessions, querying Steam time, creating recovery codes, or handling login/mobile confirmations.

## Install from this checkout

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
steamguard-pc --help
```

For development:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

## Quick start

Run the guided setup:

```powershell
steamguard-pc setup
```

Setup offers three paths:

1. Sign in and add a new mobile authenticator in SteamGuardPC.
2. Sign in only, storing the Steam Community session used by confirmation commands.
3. Import an existing Steam Desktop Authenticator `.maFile`.

If you already have a `.maFile`:

```powershell
steamguard-pc setup --mafile C:\path\to\account.maFile
```

Encrypted SDA `.maFile` imports prompt for the SDA passkey and require the matching `manifest.json` beside the file. When a `.maFile` contains SDA session tokens or cookies, SteamGuardPC imports them and can skip manual cookie setup.

After setup:

```powershell
steamguard-pc accounts
steamguard-pc code STEAMID64 --steam-time
steamguard-pc login-confirmations STEAMID64
steamguard-pc confirmations STEAMID64
```

## Common workflows

### Generate a login code

```powershell
steamguard-pc code STEAMID64
steamguard-pc code STEAMID64 --steam-time
```

`--steam-time` asks Steam for the current server time before generating the code. Use it if Steam rejects local-clock codes.

### Approve a Steam login confirmation

```powershell
steamguard-pc login-confirmations STEAMID64
steamguard-pc approve-login STEAMID64 CLIENT_ID
steamguard-pc deny-login    STEAMID64 CLIENT_ID
```

Login confirmations are Steam sign-in approval requests for this account. SteamGuardPC refreshes the stored MobileApp access token, shows the request IP address, approximate location, platform, and device name Steam reports, then requires an exact typed phrase before approving or denying the selected login. Approve only requests you recognize.

### Review and act on confirmations

```powershell
steamguard-pc confirmations STEAMID64
steamguard-pc approve STEAMID64 CONFIRMATION_ID
steamguard-pc cancel  STEAMID64 CONFIRMATION_ID
```

Single confirmation actions fetch the current confirmation, show its details, try to show a trade-offer id when available, then require an exact typed phrase before submitting.

Batch actions are also available:

```powershell
steamguard-pc approve-all STEAMID64
steamguard-pc cancel-all  STEAMID64
```

`approve-all` only submits when every displayed item is a Trade or Market listing confirmation. `cancel-all` cancels every displayed confirmation after exact typed consent.

### Refresh or set Steam Community cookies

Confirmation commands need a valid Steam Community session. Refresh it by signing in:

```powershell
steamguard-pc login ACCOUNT_NAME
```

Or copy cookies manually:

```powershell
steamguard-pc cookie-guide
$env:STEAMGUARDPC_STEAM_LOGIN_SECURE = "..."
$env:STEAMGUARDPC_SESSIONID = "..."
steamguard-pc set-cookies STEAMID64
```

Only `steamLoginSecure` and `sessionid` are needed. Treat both like passwords.

### Back up and restore

```powershell
steamguard-pc export-backup C:\private\steamguard.sgbak [STEAMID64 ...]
steamguard-pc import-backup C:\private\steamguard.sgbak
```

Backups use Argon2id key derivation, AES-256-CBC encryption, and HMAC-SHA512 authentication before decrypting. The passphrase must be at least 16 characters. Store the backup and passphrase separately; SteamGuardPC cannot recover a lost passphrase.

Revocation codes are excluded from backups by default. Include them only for private offline recovery backups:

```powershell
steamguard-pc export-backup C:\private\steamguard.sgbak --include-revocation-code
```

Use `--force` to overwrite an existing backup and `--replace` when importing over matching local accounts.

### Remove a mobile authenticator

```powershell
steamguard-pc remove-authenticator STEAMID64
```

This sends Steam the stored R##### revocation code over the stored MobileApp session and asks Steam to return the account to Steam Guard email codes. Steam warns that removing a mobile authenticator reduces account security and prevents trading or Community Market selling for 15 days. After Steam confirms removal, SteamGuardPC deletes local authenticator secrets but keeps local account metadata and sign-in/session tokens; run steamguard-pc accounts --delete STEAMID64 to remove all local account data.

### Revocation and recovery codes

```powershell
steamguard-pc revocation-code STEAMID64
steamguard-pc recovery-codes STEAMID64
```

The revocation code is Steam's `R#####` authenticator-removal code. `remove-authenticator` uses it to ask Steam to remove the mobile authenticator and never prints it. `revocation-code` reveals it only after exact typed consent. Recovery codes are one-time Steam account recovery codes; newly created codes are printed once and are not saved.

## Command reference

Run `steamguard-pc COMMAND -h` for command-specific options.

| Command | Purpose |
| --- | --- |
| `setup [--mafile PATH] [--skip-cookies]` | Guided setup. Enroll, sign in for cookies, or import a `.maFile`. |
| `enroll [ACCOUNT_NAME]` | Sign in, add a mobile authenticator, store its secrets, and finalize with Steam's activation code. |
| `login [ACCOUNT_NAME]` | Sign in and store refresh/access tokens plus Steam Community session data. |
| `accounts [--delete STEAMID64]` | List local accounts or delete one local account and all of its stored secrets. Steam is not changed. |
| `code STEAMID64 [--timestamp UNIX_TIME] [--steam-time]` | Print a Steam Guard login code and seconds remaining. |
| `login-confirmations STEAMID64` | List pending Steam login confirmations. |
| `approve-login STEAMID64 CLIENT_ID` | Approve one Steam login confirmation. |
| `deny-login STEAMID64 CLIENT_ID` | Deny one Steam login confirmation. |
| `confirmations STEAMID64` | List pending mobile confirmations. |
| `approve STEAMID64 CONFIRMATION_ID` | Approve one pending confirmation after review and exact typed consent. |
| `cancel STEAMID64 CONFIRMATION_ID` | Cancel one pending confirmation after review and exact typed consent. |
| `approve-all STEAMID64` | Approve the current batch only if every displayed item is Trade or Market listing. |
| `cancel-all STEAMID64` | Cancel every displayed pending confirmation after exact typed consent. |
| `find-mafiles [DIR ...]` | Search common SDA locations or supplied directories for `.maFile` files. |
| `import-mafile PATH` | Import shared/identity secrets and SDA session fields from a Steam Desktop Authenticator file. |
| `cookie-guide` | Show browser steps for copying Steam Community cookies. |
| `set-cookies STEAMID64` | Store `steamLoginSecure` and `sessionid` from environment variables or hidden prompts. |
| `revocation-code STEAMID64` | Reveal the stored authenticator revocation code after exact typed consent. |
| `remove-authenticator STEAMID64` | Remove the mobile authenticator from Steam after exact typed consent and delete local authenticator secrets. |
| `recovery-codes STEAMID64` | Create and print one-time Steam recovery codes after exact typed consent. |
| `export-backup PATH [STEAMID64 ...]` | Export selected accounts, secrets, and session tokens to an encrypted backup. |
| `import-backup PATH [--replace]` | Import accounts from an encrypted SteamGuardPC backup. |

## Storage and security model

SteamGuardPC stores metadata and secrets separately:

- `%APPDATA%\SteamGuardPC\config.json` stores non-secret metadata: SteamID64, account name, generated device id, and import timestamp.
- Windows secret storage stores sensitive fields under the `SteamGuardPC` service: shared secret, identity secret, revocation code, refresh/access tokens, Steam Community cookies, and imported SDA metadata.
- `remove-authenticator` deletes local authenticator material (`shared_secret`, `identity_secret`, `revocation_code`, `serial_number`, `token_gid`, and `uri`) after Steam confirms removal. `accounts --delete` removes the whole local account and all stored secrets.
- Per-account lock files live under `%APPDATA%\SteamGuardPC\locks` to prevent overlapping confirmation or deletion operations.
- Set `STEAMGUARDPC_CONFIG_DIR` to move the config and lock directory.

Steam passwords are prompted only during `login` or `enroll` and are not stored. Sensitive operations require exact typed consent, and the CLI avoids printing secrets except for commands whose purpose is to reveal newly created or stored recovery material. `.maFile` files and backups contain authenticator secrets; keep them out of Git, Downloads, cloud-sync folders, logs, screenshots, and issue reports.

## Notes and limits

- Adding a new authenticator changes Steam account security state and can affect trade or market holds.
- Use `remove-authenticator` to remove the mobile authenticator from Steam. Deleting an account with `accounts --delete` only removes local metadata and secrets.
- Sign-in supports email codes, mobile authenticator codes, and email/mobile approval prompts; use `login-confirmations`/`approve-login`/`deny-login` to approve or deny other pending Steam login requests. Unsupported Steam risk checks or agreement prompts must be completed outside this tool before retrying.
- If confirmations report an expired session, run `steamguard-pc login ACCOUNT_NAME` or `steamguard-pc set-cookies STEAMID64`.
- If Steam rejects generated codes, sync Windows time or use `steamguard-pc code STEAMID64 --steam-time`.
