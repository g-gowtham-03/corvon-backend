ALTER TABLE recovery_challenges ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE user_contacts ADD COLUMN IF NOT EXISTS label_ciphertext text;

-- FCM tokens from the earlier schema were plaintext. Invalidate them and require re-registration.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fcm_token_ciphertext text;
ALTER TABLE devices DROP COLUMN IF EXISTS fcm_token;

-- Never leave legacy coordinates in plaintext. Stop and require an explicit encrypted export/import
-- if the pre-encryption schema contains reports; an empty legacy table upgrades automatically.
ALTER TABLE location_reports ADD COLUMN IF NOT EXISTS location_ciphertext text;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='location_reports' AND column_name='latitude') THEN
    IF EXISTS (SELECT 1 FROM location_reports) THEN
      RAISE EXCEPTION 'Legacy plaintext location reports exist; export and encrypt them before migration 002';
    END IF;
    ALTER TABLE location_reports DROP COLUMN latitude, DROP COLUMN longitude, DROP COLUMN accuracy_meters;
  END IF;
END $$;
ALTER TABLE location_reports ALTER COLUMN location_ciphertext SET NOT NULL;

ALTER TABLE otp_dispatches ADD COLUMN IF NOT EXISTS destination_hash char(64);
UPDATE otp_dispatches d SET destination_hash = o.destination_hash
FROM otp_challenges o
WHERE d.destination_hash IS NULL
  AND ((d.registration_id IS NOT NULL AND o.registration_id=d.registration_id)
    OR (d.recovery_challenge_id IS NOT NULL AND o.recovery_challenge_id=d.recovery_challenge_id))
  AND d.contact_type=o.contact_type;
UPDATE otp_dispatches SET destination_hash=md5(id::text)||md5(id::text) WHERE destination_hash IS NULL;
ALTER TABLE otp_dispatches ALTER COLUMN destination_hash SET NOT NULL;

ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS status_token_hash char(64);
UPDATE recovery_requests SET status_token_hash=md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text) WHERE status_token_hash IS NULL;
ALTER TABLE recovery_requests ALTER COLUMN status_token_hash SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS recovery_requests_status_token_hash_uidx ON recovery_requests(status_token_hash);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key char(64) PRIMARY KEY,
  hits integer NOT NULL CHECK (hits > 0),
  reset_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS otp_dispatches_destination_time_idx ON otp_dispatches(destination_hash,contact_type,sent_at DESC);
