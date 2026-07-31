# SteamGuardPC usage

This guide covers normal CLI workflows. Install the package first using [README.md](README.md), and read the security notes before storing account credentials or authenticator secrets.

Examples assume this checkout install path:

```powershell
.\.venv\Scripts\steamguard-pc <command>
```

## Safety quick facts

- Secrets are stored in keyring-backed secret storage.
- `enroll` changes account security state and can affect Steam trade or market restrictions.
- The Steam Guard revocation code is `R` followed by five digits. It can remove the authenticator.
- `approve` and `cancel` act on one selected confirmation and require exact typed consent.
- Steam Guard codes are time based. Keep Windows time synchronized.

## First run

Use the setup wizard:

```powershell
.\.venv\Scripts\steamguard-pc setup
```

It offers three paths:

1. Add a new mobile authenticator in this app.
2. Sign in only, to store or refresh Steam Community session cookies.
3. Import an existing decrypted `.maFile`.

After setup, verify the stored account and generate a code:

```powershell
.\.venv\Scripts\steamguard-pc accounts
.\.venv\Scripts\steamguard-pc code <steamid64>
```

List confirmations when the account has pending Steam mobile actions:

```powershell
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

If setup enrolled a new authenticator, reveal and back up the revocation code in a private terminal:

```powershell
.\.venv\Scripts\steamguard-pc revocation-code <steamid64>
```

## Workflows

### Add a new authenticator

Use this only when you intend SteamGuardPC to add a mobile authenticator to the account.

```powershell
.\.venv\Scripts\steamguard-pc enroll <account_name>
```

If `<account_name>` is omitted, the CLI prompts for it.

What happens:

1. Prompts for the Steam password without echoing it.
2. Handles Steam's login challenge.
3. Stores refresh/session credentials in keyring.
4. Warns that adding an authenticator changes account security state.
5. Requires the exact phrase:

   ```text
   ADD AUTHENTICATOR <steamid64>
   ```

6. Calls Steam's add-authenticator endpoint without adding or linking a phone number.
7. Stores the generated authenticator secrets before finalization.
8. Prints the `R#####` revocation code if Steam returns one. Store it offline immediately.
9. Completes Steam's registration validation by asking for the activation code from email or SMS.
10. Finalizes the authenticator.

If no activation code arrives, enter this exact phrase at the activation-code prompt:

```text
SEND ACTIVATION EMAIL <steamid64>
```

SteamGuardPC then asks Steam to send an activation-code email and prompts again.

### Reveal and back up the revocation code

The revocation code can remove the authenticator from the account. It is not the seven-digit recovery code Steam asks for during website sign-in recovery.

```powershell
.\.venv\Scripts\steamguard-pc revocation-code <steamid64>
```

Before printing the code, the command requires:

```text
SHOW REVOCATION CODE <steamid64>
```

Cancelled output:

```text
Revocation code display cancelled.
```

Successful output:

```text
Steam Guard revocation code for <account_name-or-steamid64> (<steamid64>): <revocation_code>
```

### Sign in or refresh the Steam Community session

Use `login` when confirmations fail because cookies expired, or when you want to refresh stored web-session credentials.

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

If `<account_name>` is omitted, the CLI prompts for it.

The command:

1. Prompts for the Steam password without echoing it.
2. Handles Steam Guard challenges.
3. If this account's `shared_secret` is already stored, generates and submits the current mobile authenticator code without printing it.
4. Stores or updates `refresh_token`, `access_token`, `steamLoginSecure`, and `sessionid`.

### Import an existing decrypted `.maFile`

Use this if you already have a decrypted Steam Desktop Authenticator-compatible `.maFile`.

```powershell
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

The command:

1. Warns when the path is under a Git checkout, `Downloads`, or a cloud-sync folder.
2. Parses the JSON file.
3. Validates required fields, including `steamid`, `shared_secret`, and `identity_secret`.
4. Stores secrets in keyring.
5. Writes only metadata to config.
6. Prints the account label and SteamID64, never secret values.

Encrypted or unsupported files are rejected with:

```text
encrypted or unsupported .maFile; decrypt it in the source app and retry
```

### Find `.maFile` candidates

Search common locations:

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles
```

Search specific directories:

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles C:\Users\you\Documents D:\Backups
```

### Generate a Steam Guard login code

```powershell
.\.venv\Scripts\steamguard-pc code <steamid64>
```

Output:

```text
ABCDE expires_in=Ns
Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.
```

`expires_in` is the number of seconds left in the current 30-second Steam Guard window.

`--timestamp` is for deterministic troubleshooting and tests:

```powershell
.\.venv\Scripts\steamguard-pc code <steamid64> --timestamp 1700000000
```

Do not use a fixed timestamp for normal logins.

### List and act on confirmations

List pending mobile confirmations:

```powershell
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

Rows are tab-separated:

```text
id    type_name-or-type    creator_id-or--    headline-or--    summary-or--
```

No pending confirmations:

```text
No pending confirmations.
```

Approve one selected confirmation:

```powershell
.\.venv\Scripts\steamguard-pc approve <steamid64> <confirmation_id>
```

Cancel one selected confirmation:

```powershell
.\.venv\Scripts\steamguard-pc cancel <steamid64> <confirmation_id>
```

Before acting, SteamGuardPC prints the selected confirmation details:

- `id`
- `type`
- `creator_id`
- `headline`
- `summary`

It then requires the exact phrase:

```text
APPROVE <confirmation_id>
```

or:

```text
CANCEL <confirmation_id>
```

If the phrase differs, the command returns exit code `1` without calling Steam. Success is reported only after Steam accepts the action and a refreshed confirmation list no longer contains the target.

### Manual cookie fallback

Prefer `login`. Use manual cookies only when you cannot complete Steam sign-in through the CLI.

Show browser instructions:

```powershell
.\.venv\Scripts\steamguard-pc cookie-guide
```

Store cookies interactively:

```powershell
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

Or pass both values through environment variables:

```powershell
$env:STEAMGUARDPC_STEAM_LOGIN_SECURE = "<steamLoginSecure>"
$env:STEAMGUARDPC_SESSIONID = "<sessionid>"
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
Remove-Item Env:STEAMGUARDPC_STEAM_LOGIN_SECURE
Remove-Item Env:STEAMGUARDPC_SESSIONID
```

Setting only one cookie environment variable is rejected.

## Command reference

| Command | Purpose |
| --- | --- |
| `setup [--mafile PATH] [--skip-cookies]` | Guided first run. With `--mafile`, imports that file directly. |
| `enroll [ACCOUNT_NAME]` | Adds and finalizes a new mobile authenticator after exact typed consent. |
| `login [ACCOUNT_NAME]` | Signs in and stores or refreshes Steam Community session credentials. |
| `accounts` | Lists stored account metadata. Secrets are never printed. |
| `revocation-code STEAMID64` | Reveals the stored `R#####` revocation code after exact typed consent. |
| `import-mafile PATH` | Imports a decrypted `.maFile` into keyring-backed storage. |
| `find-mafiles [DIR ...]` | Searches common or supplied directories for `.maFile` files. |
| `code STEAMID64 [--timestamp UNIX_TIME]` | Prints the current Steam Guard login code and seconds remaining. |
| `confirmations STEAMID64` | Lists pending mobile confirmations. |
| `approve STEAMID64 CONFIRMATION_ID` | Approves one selected confirmation after exact typed consent. |
| `cancel STEAMID64 CONFIRMATION_ID` | Cancels one selected confirmation after exact typed consent. |
| `cookie-guide` | Prints browser steps for manual cookie fallback. |
| `set-cookies STEAMID64` | Stores `steamLoginSecure` and `sessionid` manually. |

Run command-specific help with:

```powershell
.\.venv\Scripts\steamguard-pc <command> -h
```

## Troubleshooting

### `No accounts imported.`

Run one setup path:

```powershell
.\.venv\Scripts\steamguard-pc setup
.\.venv\Scripts\steamguard-pc enroll <account_name>
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

### `missing shared_secret for <steamid64>`

The account has metadata but no stored login-code secret. Enroll an authenticator or import a `.maFile` for that account.

### `missing identity_secret for <steamid64>`

The account has metadata but no stored confirmation secret. Enroll an authenticator or import a `.maFile` for that account.

### `missing revocation_code for <steamid64>`

The account has metadata but no stored Steam Guard revocation code. Re-import a `.maFile` that contains `revocation_code`, or use the offline copy you saved during enrollment.

### `missing Steam Community cookies for <steamid64>`

Refresh the session:

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

If login is unavailable, use the manual fallback:

```powershell
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

### Steam rejects a login code

- Confirm the `steamid64` is correct.
- Sync Windows time.
- Generate a fresh code near the start of its 30-second window.

### Confirmations show auth/session errors

Run:

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```
