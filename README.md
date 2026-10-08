# Securing Acme Bank

A Codecademy project to find and fix security vulnerabilities in **Acme Bank**, a deliberately insecure Node.js/Express banking app. Users can log in, transfer money, download their records, view a public ledger and post on a public forum.

The original app (`app.js`) was open to cross-site scripting (XSS), SQL injection, cross-site request forgery (CSRF) and session theft. This project secured it across six tickets, each tested by attacking the running app before and after the fix.

## Tech stack

- **Node.js** + **Express**: web server
- **EJS**: HTML templates (`views/`)
- **SQLite** (`sqlite3`): database (`bank_sample.db`)
- **express-session**: login sessions
- Security packages: **helmet**, **express-validator**, **csurf**

## Getting started

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create a `.env` file in the project root with a random session secret:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
   ```
   SESSION_SECRET=paste-the-generated-value-here
   ```
   `.env` is git-ignored, so the secret is never committed.
3. Start the app (requires Node.js 20.12+ for the built-in `.env` loader):
   ```bash
   node app.js
   ```
4. Open http://localhost:3000.

> On production (HTTPS), start with `NODE_ENV=production` so the session cookie gets the `Secure` flag.

## What was secured

### 1. XSS protection with Helmet

**Problem:** The app sent no security headers, so the browser would run any script that got into a page.

**Fix:** Added `helmet` with a **Content Security Policy (CSP)**. Scripts and styles may only load from the app itself and the Bootstrap CDN (`cdn.jsdelivr.net`). An injected `<script>` that gets past the other defences is still blocked by the browser.

```js
"script-src": ["'self'", "https://cdn.jsdelivr.net"],
```

### 2. Secure session cookie

**Problem:** The session cookie had no security flags, and the signing secret was the hardcoded string `"secret"`.

**Fix:**

| Setting | Value | Protects against |
|---|---|---|
| `httpOnly` | `true` | XSS scripts reading the cookie via `document.cookie` |
| `secure` | `true` in production only | The cookie being sniffed on the network over plain HTTP |
| `sameSite` | `"strict"` | Other sites triggering requests that carry the cookie (CSRF) |
| `maxAge` + `rolling` | 15 minutes, reset on each request | Sessions left open on unattended devices (idle timeout) |
| `secret` | Read from `.env` | Session forgery using a known or guessable secret |

`secure` is conditional because a Secure cookie is never sent over `http://localhost`, which would silently break login during development.

### 3. Input validation and normalisation with express-validator

**Problem:** User input went straight into the database and pages. `parseInt` accepted input like `"100abc"`, and **negative transfer amounts were allowed**. A transfer of `-500` would *take* money from the recipient.

**Fix:** Added validation chains to every form. These allow only known-good input instead of trying to block known attacks:

| Route | Rules |
|---|---|
| `POST /auth` | Username trimmed, required, max 50 chars; password required, max 100 chars |
| `POST /transfer` | `account_to`: whole number ≥ 1. `amount`: whole number from **£1 to £10,000**. Both converted to numbers. |
| `POST /public_forum` | Comment trimmed, not empty, max 500 chars |
| `GET /public_ledger` | `id` optional, but if given must be a positive whole number |

Invalid transfers show a clear error message and never reach the database.

### 4. DOM-based XSS prevention

**Problem:** The forum and ledger views printed database values with EJS's **raw** output tag `<%-`. A forum post containing `<script>` ran in every visitor's browser (stored XSS).

**Fix:** Switched every user-data output to the **escaped** tag `<%=`, which HTML-encodes `< > & " '` so the browser displays them as text.

Comments are **stored exactly as typed and encoded on output**, following OWASP guidance. Escaping on input as well caused double-encoding (`Don't` displayed as `Don&#x27;t`), so input escaping was removed.

### 5. SQL injection prevention with prepared statements

**Problem:** Every query built SQL by pasting user input into the string:

```js
`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
```

Logging in as `admin'--` bypassed the password check, and the ledger search allowed `UNION SELECT` attacks that leaked usernames and passwords.

**Fix:** Converted all five vulnerable queries (login, both transfer updates, forum insert, ledger search) to **prepared statements**. The values are sent separately from the SQL and treated only as data:

```js
db.get(
  `SELECT * FROM users WHERE username = ? AND password = ?`,
  [username, password],
  callback
);
```

The ledger queries now also select only the columns the page shows, instead of `SELECT *`.

### 6. CSRF prevention with csurf

**Problem:** Any website could submit a hidden form to `/transfer`. The victim's browser would attach their session cookie, and money would move without their knowledge.

**Fix:**
- Added `csurf` middleware (session-based) to the transfer, forum and download routes.
- Exposed the token to all views via `res.locals.csrfToken`.
- Added a hidden `_csrf` field to each form that changes data:
  ```html
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  ```
- Requests with a missing or invalid token are rejected with **403 Forbidden**. The error handler is registered *after* the routes so it can catch their errors.

## Testing

Each fix was verified against the running app with `curl`. Before tests that wrote data, the database was backed up, and afterwards it was restored and confirmed unchanged by checksum.

| Attack | Result |
|---|---|
| Login as `admin'--` / `' OR '1'='1` | Rejected |
| Ledger `id=1' UNION SELECT username,password,...` | Rejected, no data leaked |
| Transfer of `-500`, `0`, `100abc`, `1 OR 1=1`, `99999` | Rejected with an error message |
| Forum post `It's fine'); DROP TABLE users;-- <script>alert(1)</script>` | Stored safely and displayed as plain text; `users` table intact |
| Forged transfer from another origin with no token / a guessed token | **403**, balances unchanged |
| Genuine transfer from the app's own form | Succeeds |

## Additional fixes

- **Native module error on Windows:** the original `node_modules` only contained a macOS build of `sqlite3`. Upgraded to `sqlite3@5.1.7`, which ships prebuilt binaries for Windows and current Node versions.
- **Forum display bug:** a new comment sometimes didn't appear until the page was refreshed, because the `INSERT` and `SELECT` ran at the same time. The `SELECT` now runs after the `INSERT` completes.

## Known remaining issues

These were outside the six tickets but would need fixing before real-world use:

- **Path traversal in `POST /download`:** the file path is built with `"history_files/" + file_name`, so `../` can read files outside that folder, including `.env`.
- **Plain-text passwords:** passwords are stored and compared unhashed. They should be hashed with `bcrypt` or `argon2`.
- **Stale balance check:** transfers check the balance saved in the session at login, which isn't updated after a transfer, so repeated transfers can overdraw the account.
- **Non-atomic transfers:** the credit and debit are two separate `UPDATE`s. They should be wrapped in a transaction so both succeed or both fail.
- **Login CSRF:** `/auth` has no CSRF token because the login page is static HTML. `sameSite: "strict"` reduces the risk.
- **Deprecated `csurf`:** used here because the course requires it. New projects should use a maintained alternative such as `csrf-csrf`.

## Note on `secured_app.js`

`secured_app.js` is the reference solution that came with the project. It was used for comparison only, and contains bugs that were **not** copied into `app.js`:

- `secure: true` on the cookie breaks login over `http://localhost`.
- The CSRF error handler is registered before the routes, so it never catches anything.
- `validator.escape(...)` isn't a function in express-validator v6, so posting to the forum crashes the server.
- The transfer `UPDATE` queries still use string interpolation.
