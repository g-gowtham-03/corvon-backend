-- Keep successful verification distinct from a consumed/expired challenge.
-- Forgot Secret must never treat an expired or attempt-exhausted OTP as verified.
ALTER TABLE otp_challenges
  ADD COLUMN IF NOT EXISTS verified_at timestamptz;
