-- 0101_provider_enroll_expiry.sql
-- DPR-178: a provider-operator enrollment token never expired. The hash is
-- single-use (activation clears it) and is never stored in plaintext, but until
-- someone redeemed it the token stayed valid FOREVER — sitting in whatever
-- email, ticket or chat message it was sent in, able to create an identity in
-- the highest-privilege domain the product has. The agent side of the same idea
-- has always been time-bounded: agent join tokens default to one hour.
--
-- Expand-only. Existing unredeemed tokens are given a 24-hour grace window from
-- the migration rather than being invalidated on upgrade or left immortal, so
-- an enrollment that is genuinely in flight completes and one that has been
-- forgotten stops being a credential.
ALTER TABLE provider_operators ADD COLUMN IF NOT EXISTS enroll_expires_at timestamptz;

UPDATE provider_operators
   SET enroll_expires_at = now() + interval '24 hours'
 WHERE enroll_token_hash IS NOT NULL
   AND enroll_expires_at IS NULL;
