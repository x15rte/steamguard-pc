# SteamGuardPC usage

Install from [README.md](README.md). Examples assume:

```powershell
.\.venv\Scripts\steamguard-pc <command>
```

## First run

```powershell
.\.venv\Scripts\steamguard-pc setup
```

Setup offers:

1. Add a new authenticator.
2. Sign in only, to refresh Steam Community cookies.
3. Import an existing `.maFile` (encrypted SDA files supported).

After setup:

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc code <steamid64>
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

### List or delete stored accounts

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc accounts --delete <steamid64>
```

Deletion removes local SteamGuardPC metadata and all stored secrets for that account. It does not remove the authenticator from Steam. It requires:

```text
DELETE ACCOUNT <steamid64>
```

## Workflows

### Add an authenticator

```powershell
.\.venv\Scripts\steamguard-pc enroll <account_name>
```

Flow:

1. Sign in to Steam.
2. Type `ADD AUTHENTICATOR <steamid64>`.
3. SteamGuardPC stores the new authenticator secrets.
4. Back up the displayed `R#####` revocation code.
5. Enter Steam's email/SMS activation code.

If no activation code arrives, enter:

```text
SEND ACTIVATION EMAIL <steamid64>
```

### Refresh session cookies

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

Use this when confirmations report session/authentication errors. If the account's `shared_secret` is stored, the required mobile code is generated without printing it.

### Import a `.maFile`

```powershell
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

Imports `steamid`, `shared_secret`, `identity_secret`, optional `revocation_code`, and metadata. Secret values are not printed. Encrypted Steam Desktop Authenticator files prompt for the SDA passkey and require the sibling `manifest.json` containing that file's salt and IV.

Find candidates:

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles
.\.venv\Scripts\steamguard-pc find-mafiles C:\Users\you\Documents D:\Backups
```

### Export or import an encrypted backup

```powershell
.\.venv\Scripts\steamguard-pc export-backup C:\path\to\steamguard.sgbak [--include-revocation-code] [<steamid64> ...]
.\.venv\Scripts\steamguard-pc import-backup C:\path\to\steamguard.sgbak
```

Export requires `EXPORT BACKUP <count> ACCOUNTS` and a backup passphrase typed twice. Import requires `IMPORT BACKUP` and the same passphrase. Backups contain authenticator secrets and session cookies, encrypted with a KeePassXC-style Argon2id + AES-256-CBC + HMAC-SHA512 profile; store the file and passphrase separately. Passphrases must be at least 16 characters.

`revocation_code` is excluded by default. Use `--include-revocation-code` only for private offline recovery backups; it prints a warning and requires `INCLUDE REVOCATION CODES <count> ACCOUNTS` before the normal export phrase. Use `--force` to overwrite an existing backup file. Use `--replace` to overwrite matching local accounts during import.

### Generate a login code

```powershell
.\.venv\Scripts\steamguard-pc code <steamid64>
```

Output:

```text
ABCDE expires_in=Ns
Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.
```

`--timestamp UNIX_TIME` is for deterministic troubleshooting and tests.

### Confirmations

```powershell
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
.\.venv\Scripts\steamguard-pc approve <steamid64> <confirmation_id>
.\.venv\Scripts\steamguard-pc cancel <steamid64> <confirmation_id>
.\.venv\Scripts\steamguard-pc approve-all <steamid64>
.\.venv\Scripts\steamguard-pc cancel-all <steamid64>
```

Rows are tab-separated:

```text
id    type_name-or-type    creator_id-or--    headline-or--    summary-or--
```

Before acting, SteamGuardPC prints the selected confirmation or every confirmation in the displayed batch, then requires one exact phrase:

```text
APPROVE <confirmation_id>
CANCEL <confirmation_id>
APPROVE ALL <count> CONFIRMATIONS <steamid64>
CANCEL ALL <count> CONFIRMATIONS <steamid64>
```

Single-confirmation success is reported after Steam accepts the action and the refreshed list no longer contains the target. Batch commands act only on the reviewed list shown before the consent prompt.

### Revocation code

```powershell
.\.venv\Scripts\steamguard-pc revocation-code <steamid64>
```

Requires:

```text
SHOW REVOCATION CODE <steamid64>
```

### Recovery codes

```powershell
.\.venv\Scripts\steamguard-pc recovery-codes <steamid64>
```

Requires:

```text
CREATE RECOVERY CODES <steamid64>
```

Steam may ask for an email/SMS confirmation code. SteamGuardPC prints the generated one-time codes once and does not save them.

### Manual cookie setup

```powershell
.\.venv\Scripts\steamguard-pc cookie-guide
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

Environment variables are also accepted when both are set:

```powershell
$env:STEAMGUARDPC_STEAM_LOGIN_SECURE = "<steamLoginSecure>"
$env:STEAMGUARDPC_SESSIONID = "<sessionid>"
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
Remove-Item Env:STEAMGUARDPC_STEAM_LOGIN_SECURE
Remove-Item Env:STEAMGUARDPC_SESSIONID
```

## Command reference

| Command | Purpose |
| --- | --- |
| `setup [--mafile PATH] [--skip-cookies]` | Guided first run. |
| `enroll [ACCOUNT_NAME]` | Add and finalize a mobile authenticator. |
| `login [ACCOUNT_NAME]` | Refresh Steam Community session credentials. |
| `accounts [--delete STEAMID64]` | List stored account metadata, or delete one local account after consent. |
| `revocation-code STEAMID64` | Reveal the stored `R#####` code after consent. |
| `recovery-codes STEAMID64` | Create one-time recovery codes after consent. |
| `import-mafile PATH` | Import a `.maFile`; encrypted SDA files prompt for the SDA passkey. |
| `export-backup PATH [STEAMID64 ...] [--force] [--include-revocation-code]` | Write an encrypted SteamGuardPC backup. |
| `import-backup PATH [--replace]` | Import an encrypted SteamGuardPC backup. |
| `find-mafiles [DIR ...]` | Find `.maFile` files. |
| `code STEAMID64 [--timestamp UNIX_TIME]` | Print a login code. |
| `confirmations STEAMID64` | List pending confirmations. |
| `approve STEAMID64 CONFIRMATION_ID` | Approve one confirmation. |
| `cancel STEAMID64 CONFIRMATION_ID` | Cancel one confirmation. |
| `approve-all STEAMID64` | Review and approve every displayed confirmation. |
| `cancel-all STEAMID64` | Review and cancel every displayed confirmation. |
| `cookie-guide` | Show manual cookie instructions. |
| `set-cookies STEAMID64` | Store Community cookies manually. |

Run command help with:

```powershell
.\.venv\Scripts\steamguard-pc <command> -h
```

## Troubleshooting

| Message / symptom | Action |
| --- | --- |
| `No accounts imported.` | Run `setup`, `enroll`, or `import-mafile`. |
| `missing shared_secret` | Enroll an authenticator or import a `.maFile`. |
| `missing identity_secret` | Enroll an authenticator or import a `.maFile`. |
| `missing revocation_code` | Use the offline copy saved during enrollment or re-import a file that has it. |
| `missing Steam Community cookies` | Run `login <account_name>` or `set-cookies <steamid64>`. |
| Steam rejects a code | Check SteamID64, sync Windows time, generate a fresh code. |
| Confirmation auth/session errors | Run `login <account_name>`. |
