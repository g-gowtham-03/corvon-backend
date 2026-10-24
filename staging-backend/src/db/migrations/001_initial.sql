CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE user_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_type text NOT NULL CHECK (contact_type IN ('phone','email','emergency')),
  value_ciphertext text NOT NULL, label_ciphertext text, lookup_hash char(64) NOT NULL, verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(user_id, contact_type), UNIQUE(contact_type, lookup_hash)
);
CREATE TABLE registrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL, secret_issued_at timestamptz, secret_confirmed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE recovery_credentials (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  verifier text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), confirmed_at timestamptz
);
CREATE TABLE otp_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), registration_id uuid REFERENCES registrations(id) ON DELETE CASCADE,
  recovery_challenge_id uuid, contact_type text NOT NULL CHECK (contact_type IN ('phone','email','emergency')),
  destination_hash char(64) NOT NULL, verifier char(64) NOT NULL, expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0), consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), CHECK ((registration_id IS NOT NULL) <> (recovery_challenge_id IS NOT NULL))
);
CREATE INDEX otp_challenges_active_idx ON otp_challenges(expires_at) WHERE consumed_at IS NULL;
CREATE TABLE recovery_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL, completed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE otp_dispatches (
  id bigserial PRIMARY KEY, registration_id uuid REFERENCES registrations(id) ON DELETE CASCADE,
  recovery_challenge_id uuid REFERENCES recovery_challenges(id) ON DELETE CASCADE,
  contact_type text NOT NULL CHECK (contact_type IN ('phone','email','emergency')),
  destination_hash char(64) NOT NULL,
  sent_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((registration_id IS NOT NULL) <> (recovery_challenge_id IS NOT NULL))
);
CREATE INDEX otp_dispatches_recent_idx ON otp_dispatches(sent_at);
ALTER TABLE otp_challenges ADD CONSTRAINT otp_recovery_challenge_fk FOREIGN KEY (recovery_challenge_id) REFERENCES recovery_challenges(id) ON DELETE CASCADE;
CREATE TABLE devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id text NOT NULL, fcm_token_ciphertext text, enrolled_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
  last_seen_at timestamptz, UNIQUE(user_id, installation_id)
);
CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE, scope text NOT NULL CHECK (scope IN ('full','dashboard')),
  token_kind text NOT NULL DEFAULT 'access' CHECK (token_kind IN ('access','refresh')),
  session_family uuid NOT NULL,
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL, expires_at timestamptz NOT NULL,
  revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE login_failures (
  lookup_hash char(64) PRIMARY KEY, failures integer NOT NULL DEFAULT 0,
  locked_until timestamptz, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE recovery_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('active','stopped','expired')),
  status_token_hash char(64) NOT NULL UNIQUE,
  authorized_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, stopped_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_requests_active_idx ON recovery_requests(user_id, expires_at) WHERE status = 'active';
CREATE TABLE location_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), request_id uuid NOT NULL REFERENCES recovery_requests(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  location_ciphertext text NOT NULL, captured_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(), source text NOT NULL DEFAULT 'fused'
);
CREATE INDEX location_reports_request_time_idx ON location_reports(request_id, captured_at DESC);
CREATE TABLE audit_events (
  id bigserial PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  event_type text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE rate_limit_buckets (
  bucket_key char(64) PRIMARY KEY,
  hits integer NOT NULL CHECK (hits > 0),
  reset_at timestamptz NOT NULL
);
