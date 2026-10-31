# CORVON RECOVERY API

Node.js + Express 5 API with PostgreSQL migrations. This is backend Stage 2 only; it does not include the Android app or React website.

## Setup

1. Use Node.js 22 or newer and PostgreSQL 14+.
2. In the integrated Render service, keep `DATABASE_URL` for the legacy API. Set `RECOVERY_DATABASE_URL` to a separate PostgreSQL role for the Recovery API, with access only to the pre-created dedicated schema named by `DB_SCHEMA` (default `corvon_recovery`). The schema name must be a lowercase PostgreSQL identifier matching `[a-z_][a-z0-9_]*`; do not use `public`. The Recovery pool sets `search_path` to this schema alone and never falls back to `public`. Do not point `RECOVERY_DATABASE_URL` at the legacy role. Provide separate random values of at least 32 bytes for `OTP_PEPPER`, `LOOKUP_PEPPER`, `RECOVERY_SECRET_PEPPER`, and `SESSION_PEPPER`. Set `CONTACT_DATA_KEY` to a base64-encoded 32-byte key. Keep all values in the deployment secret store, never in Git.
3. Configure Twilio SMS (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`) and Resend email (`RESEND_API_KEY`, `EMAIL_FROM`) before requesting contact verification. If absent, the OTP request returns a delivery-unavailable error and no test OTP is exposed.
4. The Render start command remains `node server.js` from the repository root. The root server starts legacy routes even if Recovery secrets are not configured; in that state `/v1` returns `RECOVERY_API_UNAVAILABLE` and does not fall back to `DATABASE_URL`. Before enabling Recovery traffic, provision the dedicated schema/role in the existing PostgreSQL database and run `npm run migrate:recovery` with `RECOVERY_DATABASE_URL` configured. Do not run migrations using the legacy `DATABASE_URL`.

The migration runner requires the target database and configured schema to exist, verifies that the schema is active, and takes a PostgreSQL advisory lock while applying migrations. Its `schema_migrations` ledger is created in the configured schema. All Recovery application, rate-limit, background-job, and migration table names are unqualified and resolve through the Recovery pool's single-schema search path; a missing Recovery table therefore fails rather than falling through to a legacy table in `public`. PostgreSQL's system catalog remains available implicitly. Grant the Recovery role access only to its dedicated schema and required database connection. For local development set `RECOVERY_DATABASE_URL` and pre-create the schema named by `DB_SCHEMA`. The legacy root process continues to use `DATABASE_URL`. Production requires TLS termination, `DATABASE_SSL=true` as appropriate, managed secret storage, backups, and provider-approved sender identities. `TRUST_PROXY_HOPS` must match the actual trusted reverse-proxy hop count; leave it at 0 when clients connect directly.

## Workflow/API

- `POST /v1/registrations` — create a pending registration and store encrypted contacts; does not send OTPs. Body: `{ "username", "phone", "email", "emergencyContact": { "phone", "name?" } }`. Returns a `registrationId`, expiry, and per-contact verification states. Emergency contact name is optional.
- `POST /v1/registrations/:id/otp-challenges` — request or resend one OTP. Body: `{ "contactType": "phone" | "email" | "emergency" }`. Sends only that selected contact's OTP and returns its type and expiry, never its code.
- `POST /v1/registrations/:id/otp-verifications` — verify `{ "contactType": "phone" | "email" | "emergency", "code": "six digits" }`.
- `POST /v1/registrations/:id/secret` — generate once after all three verifications; returned exactly once.
- `POST /v1/registrations/:id/secret-confirmation` — prove the user saved it and complete account.
- `POST /v1/sessions` — phone + permanent secret login.
- `POST /v1/forgot-secret-challenges`, `POST /v1/forgot-secret-challenges/:id/verifications`, and `POST /v1/forgot-secret-challenges/:id/complete` — verify all three registered channels; response shape does not disclose account existence; no secret mutation or reveal route exists.
- `POST /v1/forgot-secret-challenges/:id/complete` — issues dashboard-only session for 30 minutes.
- `GET /v1/me/dashboard` — authenticated profile/recovery instructions.
- `POST /v1/recovery-requests` — phone + secret validates and opens 30-minute request.
- `GET /v1/recovery-requests/:id` and `POST /v1/recovery-requests/:id/stop` — status and stop using the one-time `recoveryAccessToken` from request creation in the `X-Recovery-Access-Token` header. Store this capability securely; it is separate from the permanent recovery secret.
- `POST /v1/recovery-requests/:id/location-reports` — authenticated enrolled device report, no faster than one per minute; reports older than 3 minutes are stale. Reports are retained 30 days.
- `PUT /v1/devices/current/fcm-token` — store an encrypted FCM token. The API sends a minimal data-only recovery-request notification when Firebase Admin credentials and an enrolled token are available.

All OTP challenges live for 5 minutes, allow at most 5 verification attempts, and can be attempted at most 3 dispatches per contact in 15 minutes, including provider failures. Login is delayed for 15 minutes after 5 failures (configurable). Shared API/IP rate limits are stored in PostgreSQL, so they are consistent across instances using the same database. OTP delivery requires Twilio and Resend credentials. Set `FIREBASE_SERVICE_ACCOUNT_JSON` to the Firebase service-account JSON in the deployment secret store; without it the recovery response reports `notificationStatus: "not_configured"`. Never commit provider credentials. The Android SMS fallback remains a user-initiated compose action; this API does not send SMS from a device or claim silent background SMS support.

## Test coverage

`npm test` from the repository root runs legacy contract tests and Recovery security/workflow tests. PostgreSQL API integration tests are skipped unless `CORVON_TEST_DATABASE_URL` points to a dedicated test database/schema that has had migrations applied. The integration suite uses an in-process mock HTTP provider for SMS/email; it does not configure or claim real provider delivery. Example PowerShell sequence after configuring the test environment:

```powershell
$env:RECOVERY_DATABASE_URL = $env:CORVON_TEST_DATABASE_URL
npm run migrate:recovery
npm test
```

The ordered migration set creates the dedicated Recovery tables and adds a `verified_at` marker so consumed expired or attempt-exhausted Forgot Secret OTPs cannot count as successful verification. The database integration suite covers OTP expiry and concurrent attempt limits, Forgot Secret completion, login lockout, recovery status authorization, provider failure/retry, and cross-instance PostgreSQL rate counters. Without the test database, those cases are reported as skipped/NOT TESTED.

## Security notes

OTPs and recovery secrets are never stored or logged in plaintext. The permanent secret is generated once; an Argon2id verifier is kept for later login and confirmation. Forgot Secret can only create a limited dashboard session and cannot change or reveal the permanent secret. Sessions are opaque random bearer tokens stored as keyed hashes. Location is accepted only for an active recovery request from a device enrolled to that user. This starter still requires production review, HTTPS, monitoring, backups, privacy/retention review, and deployment hardening.
