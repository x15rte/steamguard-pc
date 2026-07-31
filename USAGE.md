# SteamGuardPC usage

This guide covers day-to-day CLI usage. Install the package first using the commands in [README.md](README.md), and review the [security considerations](README.md#security-considerations) before storing account credentials or authenticator secrets.

## Recommended first run

Use the interactive setup wizard:

```powershell
.\.venv\Scripts\steamguard-pc setup
```

It offers three setup methods:

1. Sign in and add a new mobile authenticator in this app.
2. Sign in only to store or refresh Steam Community cookies.
3. Import an existing decrypted `.maFile`.

After setup, show a login code:

```powershell
.\.venv\Scripts\steamguard-pc code <steamid64>
```

List confirmations:

```powershell
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

## Workflows

### Add a new authenticator inside this app

Use this when the account does not already have a mobile authenticator managed elsewhere.

```powershell
.\.venv\Scripts\steamguard-pc enroll <account_name>
```

If you omit `<account_name>`, the CLI prompts for it.

The command:

1. Prompts for the Steam password without echoing it.
2. Starts Steam authentication.
3. Prompts for any Steam Guard email code, mobile authenticator code, or external confirmation Steam requires.
4. Stores the resulting refresh token, access token, `steamLoginSecure`, and `sessionid` in keyring.
5. Warns that adding an authenticator changes account security state.
6. Requires this exact typed consent phrase:

   ```text
   ADD AUTHENTICATOR <steamid64>
   ```

7. Calls Steam's add-authenticator endpoint.
8. Stores the generated authenticator secrets before finalization.
9. Prompts for the Steam activation code from email or SMS.
10. Finalizes the authenticator.

Example:

```powershell
.\.venv\Scripts\steamguard-pc enroll my_steam_login_name
```

The final activation code may arrive by email or SMS depending on Steam's account state. The prompt is:

```text
Steam activation code from email or SMS:
```

### Sign in only / refresh Steam Community cookies

Use this when the authenticator is already stored but confirmations fail because the Steam Community session expired.

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

If you omit `<account_name>`, the CLI prompts for it.

The command:

1. Prompts for the Steam password without echoing it.
2. Handles the Steam Guard challenge:
   - if the account's `shared_secret` is already stored, generates and submits the current mobile authenticator code without printing it;
   - otherwise prompts for the required email/mobile code or waits for external confirmation.
3. Stores/updates:
   - `refresh_token`
   - `access_token`
   - `steamLoginSecure`
   - `sessionid`
4. Updates account metadata.

Example:

```powershell
.\.venv\Scripts\steamguard-pc login my_steam_login_name
```

### Import an existing decrypted `.maFile`

Use this if you already have a decrypted Steam Desktop Authenticator-compatible `.maFile`.

```powershell
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

The command:

1. Warns if the selected path is under a Git checkout, `Downloads`, or a cloud-sync folder.
2. Reads the JSON `.maFile`.
3. Validates `steamid`, `shared_secret`, and `identity_secret`.
4. Stores secrets in keyring.
5. Writes only metadata to config.
6. Prints only the account label and SteamID64.

It rejects encrypted or unsupported `.maFile` files with:

```text
encrypted or unsupported .maFile; decrypt it in the source app and retry
```

### Find `.maFile` candidates

Search common locations:

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles
```

Search one or more specific directories:

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles C:\Users\you\Documents D:\Backups
```

The command prints matching `.maFile` paths or:

```text
No .maFile files found.
```

### Manual cookie setup fallback

Normally, prefer `login`, which obtains and stores Steam Community cookies inside the app. Manual cookie setup remains available as a fallback.

Show in-app browser instructions:

```powershell
.\.venv\Scripts\steamguard-pc cookie-guide
```

Store cookies interactively:

```powershell
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

The command prompts without echoing input:

```text
steamLoginSecure:
sessionid:
```

Or pass them through environment variables:

```powershell
$env:STEAMGUARDPC_STEAM_LOGIN_SECURE = "<steamLoginSecure>"
$env:STEAMGUARDPC_SESSIONID = "<sessionid>"
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
Remove-Item Env:STEAMGUARDPC_STEAM_LOGIN_SECURE
Remove-Item Env:STEAMGUARDPC_SESSIONID
```

Set both environment variables or neither. Setting only one is rejected.

## Subcommand reference

### `setup`

Interactive setup wizard.

```powershell
.\.venv\Scripts\steamguard-pc setup
.\.venv\Scripts\steamguard-pc setup --mafile C:\path\to\account.maFile
.\.venv\Scripts\steamguard-pc setup --mafile C:\path\to\account.maFile --skip-cookies
```

Behavior:

- Without `--mafile`, asks whether to enroll, login-only, or import a `.maFile`.
- With `--mafile`, imports that file directly.
- With `--skip-cookies`, skips the cookie setup portion after `.maFile` import.
- Prints suggested next commands after success.

### `login [ACCOUNT_NAME]`

Signs in to Steam and stores/refreshes web session credentials.

```powershell
.\.venv\Scripts\steamguard-pc login
.\.venv\Scripts\steamguard-pc login <account_name>
```

Use this when confirmations report authentication errors or after intentionally revoking old sessions.

If Steam asks for a mobile authenticator code and this account's `shared_secret` is already in keyring, the CLI generates and submits the current TOTP itself instead of prompting. It does not print the code.

### `enroll [ACCOUNT_NAME]`

Adds and finalizes a new mobile authenticator.

```powershell
.\.venv\Scripts\steamguard-pc enroll
.\.venv\Scripts\steamguard-pc enroll <account_name>
```

Use only when you intend to add a new authenticator to the account. It requires the explicit typed phrase `ADD AUTHENTICATOR <steamid64>` before changing authenticator state.

### `accounts`

Lists imported or enrolled account metadata.

```powershell
.\.venv\Scripts\steamguard-pc accounts
```

Output columns are tab-separated:

```text
steamid64    account_name-or--    device_id-or--
```

For an empty config:

```text
No accounts imported.
```

### `import-mafile PATH`

Imports a decrypted `.maFile`.

```powershell
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

Successful output:

```text
Imported <account_name-or-steamid64> (<steamid64>)
```

Secrets are not printed.

### `find-mafiles [DIR ...]`

Finds `.maFile` files.

```powershell
.\.venv\Scripts\steamguard-pc find-mafiles
.\.venv\Scripts\steamguard-pc find-mafiles C:\path\one C:\path\two
```

With no directories, it checks common Steam Desktop Authenticator-style locations and `./maFiles`.

### `set-cookies STEAMID64`

Stores `steamLoginSecure` and `sessionid` for an account.

```powershell
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

Prefer `login` when possible. Use `set-cookies` only when you need to paste cookies manually.

### `cookie-guide`

Prints instructions for finding Steam Community cookies in a browser.

```powershell
.\.venv\Scripts\steamguard-pc cookie-guide
```

This is a fallback guide. Prefer `login`, which handles cookies within the app.

### `code STEAMID64 [--timestamp UNIX_TIME]`

Prints a Steam Guard login code generated offline from the stored `shared_secret`.

```powershell
.\.venv\Scripts\steamguard-pc code <steamid64>
.\.venv\Scripts\steamguard-pc code <steamid64> --timestamp 1700000000
```

Normal output:

```text
ABCDE expires_in=Ns
Clock must be synchronized with Steam; sync Windows time if Steam rejects this code.
```

`--timestamp` is for deterministic troubleshooting and tests. Do not use it for normal logins.

### `confirmations STEAMID64`

Lists pending mobile confirmations.

```powershell
.\.venv\Scripts\steamguard-pc confirmations <steamid64>
```

Each confirmation row is tab-separated:

```text
id    type_name-or-type    creator_id-or--    headline-or--    summary-or--
```

For no pending confirmations:

```text
No pending confirmations.
```

If Steam reports authentication failure, run:

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

### `approve STEAMID64 CONFIRMATION_ID`

Approves one selected confirmation.

```powershell
.\.venv\Scripts\steamguard-pc approve <steamid64> <confirmation_id>
```

Before acting, it displays:

- `id`
- `type`
- `creator_id`
- `headline`
- `summary`

It then requires the exact phrase:

```text
APPROVE <confirmation_id>
```

If the phrase differs, it prints:

```text
Approval cancelled.
```

and returns exit code `1` without calling the approval endpoint.

Success is printed only after the app refreshes the confirmation list and verifies that the target disappeared:

```text
Approved <confirmation_id>.
```

### `cancel STEAMID64 CONFIRMATION_ID`

Cancels one selected confirmation.

```powershell
.\.venv\Scripts\steamguard-pc cancel <steamid64> <confirmation_id>
```

Before acting, it displays the same target details as `approve`.

It requires the exact phrase:

```text
CANCEL <confirmation_id>
```

If the phrase differs, it prints:

```text
Approval cancelled.
```

and returns exit code `1` without calling the cancel endpoint.

Success is printed only after the app refreshes the confirmation list and verifies that the target disappeared:

```text
Cancelled <confirmation_id>.
```

## Troubleshooting

### `No accounts imported.`

Run one of:

```powershell
.\.venv\Scripts\steamguard-pc setup
.\.venv\Scripts\steamguard-pc enroll <account_name>
.\.venv\Scripts\steamguard-pc import-mafile C:\path\to\account.maFile
```

### `missing shared_secret for <steamid64>`

The account has metadata but no stored login-code secret. Enroll an authenticator or import a `.maFile` for that account.

### `missing identity_secret for <steamid64>`

The account has metadata but no stored confirmation secret. Enroll an authenticator or import a `.maFile` for that account.

### `missing Steam Community cookies for <steamid64>`

Run:

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```

or the manual fallback:

```powershell
.\.venv\Scripts\steamguard-pc set-cookies <steamid64>
```

### `encrypted or unsupported .maFile; decrypt it in the source app and retry`

The selected file is not plaintext JSON. Export or decrypt it in the source app first, or use `enroll` to add a new authenticator through this app.

### Steam rejects a login code

- Check that you selected the correct `steamid64`.
- Sync Windows time.
- Generate a fresh code close to the start of its 30-second window.

### Confirmations show auth/session errors

Refresh the session:

```powershell
.\.venv\Scripts\steamguard-pc login <account_name>
```
