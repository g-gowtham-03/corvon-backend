# Recovery PostgreSQL role and schema setup

Administrator review template for isolating the Recovery API in the existing PostgreSQL database. This document does not authorize running the SQL. Do not run it against production until the database owner explicitly approves the target and migration window.

## Verified application behavior

- The legacy process continues to use `DATABASE_URL`.
- The Recovery pool uses only `RECOVERY_DATABASE_URL` and sets `search_path` to `DB_SCHEMA` alone. The configured schema is validated as a lowercase identifier; `public`, `pg_catalog`, and `information_schema` are rejected.
- The host refuses to enable Recovery if its database URL uses the same username as `DATABASE_URL`.
- The migration runner requires the configured schema to exist and be active. It creates `schema_migrations` in that schema, takes an advisory lock, and applies each migration transactionally.
- The migration runner and application share `RECOVERY_DATABASE_URL`; the current code has no separate migration-role setting. In the tested Render database, the schema itself is owned by the existing database administrator/owner role. The Recovery role has explicit `USAGE` and `CREATE` on that schema, and owns the tables and sequences it creates. The migration runner checks that the configured schema exists and is active; it does not require the Recovery role to own the schema.

## PostgreSQL privileges required

The dedicated role needs:

1. `LOGIN` and effective `CONNECT` to the existing database. In the tested database, `CONNECT` is available through the existing database ACL; grant it directly to the Recovery role only if that ACL does not provide it.
2. `USAGE` and `CREATE` on the dedicated `corvon_recovery` schema. The schema may remain owned by the database administrator/owner role; do not grant the Recovery role database-level `CREATE` merely to transfer schema ownership.
3. Ownership of the tables and sequences created by the Recovery migration runner. Since migrations connect as this role, PostgreSQL assigns those objects to it; ownership gives runtime DML and sequence use as well as later migration DDL.
4. No membership for the Recovery role in the legacy role (or any role that grants legacy privileges), and no grants on legacy tables. `NOINHERIT` is an additional safeguard, not a substitute for having no such memberships.

Do not revoke privileges from `PUBLIC`, alter the legacy role, change legacy schema/table ownership or ACLs, or grant the Recovery role access to legacy objects as part of this setup. In the tested database, `public` contained no tables and the Recovery role had no `CREATE` privilege there (it did have effective `USAGE` through the existing `PUBLIC` schema ACL). The application's `search_path` isolation prevents unqualified Recovery SQL from falling through to `public`; PostgreSQL permissions must still be checked because a schema-qualified query could access an object if the role separately had privileges.

## SQL template

Have the DBA replace the three uppercase placeholders with the exact existing database name, a new role name, and the chosen non-public schema name. Use valid unquoted PostgreSQL identifiers (lowercase letters, digits, underscores; begin with a letter or underscore). The password is deliberately omitted: after creating the role, set it interactively with `\password RECOVERY_ROLE_NAME` in `psql`, so it is not embedded in this file or a SQL command. Supply the resulting connection string only through the deployment secret store.

Run the first two statements as a PostgreSQL administrator connected to the intended existing database. Then connect to that same database as administrator and run the schema statement. `CREATE ROLE` and `CREATE SCHEMA` intentionally fail if either name already exists; stop and inspect rather than reusing or altering an existing role/schema.

```sql
-- Replace placeholders before execution. No legacy object is changed.
CREATE ROLE RECOVERY_ROLE_NAME
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- Optional: uncomment only if the existing database ACL does not already give
-- this role CONNECT and the administrator has permission to grant it.
-- GRANT CONNECT ON DATABASE EXISTING_DATABASE_NAME TO RECOVERY_ROLE_NAME;

-- Connect to EXISTING_DATABASE_NAME as its administrator/owner. The schema
-- remains owned by that administrator; the application role gets only the
-- schema privileges it needs. Do not grant it database-level CREATE.
CREATE SCHEMA RECOVERY_SCHEMA_NAME;
GRANT USAGE, CREATE ON SCHEMA RECOVERY_SCHEMA_NAME TO RECOVERY_ROLE_NAME;
```

Set the role password securely with `psql`'s interactive `\password RECOVERY_ROLE_NAME` command. Confirm that the role is not a member of the legacy role and has no effective privileges on the legacy schema/tables before configuring the service.

## Read-only verification queries

Replace the role/schema/database placeholders. Run as an administrator in the target database. These queries inspect metadata and privileges; they do not alter data or schema.

```sql
-- Confirm the connection is to the intended existing database.
SELECT current_database() AS connected_database;

-- Confirm the dedicated schema and its owner. In the tested setup the owner
-- is the existing database administrator/owner, not the Recovery login role.
SELECT n.nspname AS schema_name, pg_get_userbyid(n.nspowner) AS owner
FROM pg_namespace AS n
WHERE n.nspname = 'RECOVERY_SCHEMA_NAME';

-- Confirm the Recovery role is a restricted login, not a superuser/DB or role creator.
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit
FROM pg_roles
WHERE rolname = 'RECOVERY_ROLE_NAME';

-- Any returned row means the Recovery role has a role membership to investigate.
SELECT granted.rolname AS granted_role, member.rolname AS member_role, m.admin_option
FROM pg_auth_members AS m
JOIN pg_roles AS granted ON granted.oid = m.roleid
JOIN pg_roles AS member ON member.oid = m.member
WHERE member.rolname = 'RECOVERY_ROLE_NAME';

-- Confirm database CONNECT and dedicated-schema USAGE/CREATE.
SELECT has_database_privilege('RECOVERY_ROLE_NAME', current_database(), 'CONNECT') AS can_connect,
       has_schema_privilege('RECOVERY_ROLE_NAME', 'RECOVERY_SCHEMA_NAME', 'USAGE') AS schema_usage,
       has_schema_privilege('RECOVERY_ROLE_NAME', 'RECOVERY_SCHEMA_NAME', 'CREATE') AS schema_create;

-- Inspect effective access to public. Do not change public ACLs as a fix here.
SELECT has_schema_privilege('RECOVERY_ROLE_NAME', 'public', 'USAGE') AS public_usage,
       has_schema_privilege('RECOVERY_ROLE_NAME', 'public', 'CREATE') AS public_create;

-- Show any effective access to tables in public (the legacy code's default schema).
SELECT table_schema, table_name,
       has_table_privilege('RECOVERY_ROLE_NAME', format('%I.%I', table_schema, table_name), 'SELECT') AS can_select,
       has_table_privilege('RECOVERY_ROLE_NAME', format('%I.%I', table_schema, table_name), 'INSERT') AS can_insert,
       has_table_privilege('RECOVERY_ROLE_NAME', format('%I.%I', table_schema, table_name), 'UPDATE') AS can_update,
       has_table_privilege('RECOVERY_ROLE_NAME', format('%I.%I', table_schema, table_name), 'DELETE') AS can_delete
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

The membership query should return no rows. Review the public access results against the deployed legacy schema and role. If the Recovery role has any effective legacy-object access, stop and ask the DBA to design an isolation change that does not disrupt the legacy service; do not revoke shared privileges blindly.

## Recovery tables and migration sequence

`001_initial.sql` creates `users`, `user_contacts`, `registrations`, `recovery_credentials`, `otp_challenges`, `recovery_challenges`, `otp_dispatches`, `devices`, `sessions`, `login_failures`, `recovery_requests`, `location_reports`, `audit_events`, and `rate_limit_buckets`.

`002_shared_rate_limits.sql` applies security/schema updates and ensures the shared rate-limit table and supporting indexes. `003_mark_successful_otps.sql` adds `otp_challenges.verified_at`, which records only a successful OTP check; expired or attempt-exhausted challenges are consumed but never count as verified. The runner separately creates `schema_migrations` in the configured schema. A fully initialized Recovery schema therefore has the 14 application tables above plus `schema_migrations`.

Use a newly created, empty Recovery schema. Migration 001 uses plain `CREATE TABLE`, so it is not a safe initializer over pre-existing tables. Migration 002 alters and backfills Recovery tables; it drops an old plaintext `devices.fcm_token` column and will stop if it detects plaintext latitude rows in a legacy-format Recovery `location_reports` table. It must never be pointed at the legacy schema. With a genuinely empty dedicated schema, the normal ordered migration sequence is the intended path.

## Safest initialization and test sequence

1. Have the database administrator verify the target database and review this role/schema template. First test in an already available non-production database or an explicitly approved isolated test schema; do not use production for migration testing.
2. Create the new restricted role and empty dedicated schema only after approval. Grant schema `USAGE`/`CREATE` to the Recovery role. Verify the role is not a member of any legacy role and has no effective access to legacy tables using the queries above. The tested arrangement keeps schema ownership with the database administrator/owner; the Recovery role owns objects it creates inside that schema.
3. Configure `RECOVERY_DATABASE_URL` with the new role and the existing PostgreSQL host/database; keep the legacy `DATABASE_URL` unchanged. Set `DB_SCHEMA=corvon_recovery` (or the exact approved schema name). The two URLs must use different usernames.
4. Apply `npm run migrate:recovery` only to the approved non-production target and confirm that `schema_migrations` and the 14 Recovery tables exist in the dedicated schema. Run PostgreSQL integration tests there.
5. Production migration requires a separate explicit approval, verified backup/restore plan, reviewed migration output, and a rollback plan. Do not infer that a successful staging migration authorizes production migration.

## Environment variables

Integrated service configuration names (values belong in the secret manager, not this document):

- Legacy API: `DATABASE_URL` (keep existing value/role unchanged).
- Recovery database: `RECOVERY_DATABASE_URL` (same PostgreSQL service/database may be used, but a distinct restricted role); `DB_SCHEMA` (defaults to `corvon_recovery`).
- Recovery cryptographic configuration: `OTP_PEPPER`, `LOOKUP_PEPPER`, `RECOVERY_SECRET_PEPPER`, `SESSION_PEPPER`, `CONTACT_DATA_KEY`.
- Operational settings with code defaults: `PORT`, `NODE_ENV`, `TRUST_PROXY_HOPS`, `DATABASE_SSL`, `CORS_ORIGINS`, `OTP_TTL_SECONDS`, `OTP_MAX_ATTEMPTS`, `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_SECONDS`, `RECOVERY_SESSION_SECONDS`, `RECOVERY_REQUEST_SECONDS`, `LOCATION_INTERVAL_SECONDS`, `LOCATION_STALE_SECONDS`, `LOCATION_RETENTION_DAYS`, `SESSION_TTL_SECONDS`, `REFRESH_TTL_SECONDS`, `ARGON2_MEMORY_KIB`, `ARGON2_TIME_COST`, and `ARGON2_PARALLELISM`.
- Delivery providers, required for real delivery rather than startup: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, `RESEND_API_KEY`, `EMAIL_FROM`. FCM uses optional `FIREBASE_SERVICE_ACCOUNT_JSON`. `RESEND_API_URL` is optional and defaults in code.
- `PUBLIC_BASE_URL` appears in `.env.example` but is not read by the current Recovery config; it is not required by this code.

The Recovery host remains unavailable when its required Recovery URL/keys are missing. It must not fall back to `DATABASE_URL`.
