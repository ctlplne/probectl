-- 0053: Per-tenant fairness overrides for device and OTLP meters.
--
-- 0031 created the tenant_fairness override table before device_metrics_per_sec
-- and otlp_series_per_sec became served fairness meters. Additive only: NULL
-- keeps inheriting the deployment default, matching the rest of the policy
-- contract.

ALTER TABLE tenant_fairness
  ADD COLUMN IF NOT EXISTS device_metrics_per_sec double precision,
  ADD COLUMN IF NOT EXISTS otlp_series_per_sec double precision;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'tenant_fairness_device_metrics_per_sec_positive'
      AND conrelid = 'tenant_fairness'::regclass
  ) THEN
    ALTER TABLE tenant_fairness
      ADD CONSTRAINT tenant_fairness_device_metrics_per_sec_positive
      CHECK (device_metrics_per_sec IS NULL OR device_metrics_per_sec > 0) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'tenant_fairness_otlp_series_per_sec_positive'
      AND conrelid = 'tenant_fairness'::regclass
  ) THEN
    ALTER TABLE tenant_fairness
      ADD CONSTRAINT tenant_fairness_otlp_series_per_sec_positive
      CHECK (otlp_series_per_sec IS NULL OR otlp_series_per_sec > 0) NOT VALID;
  END IF;
END $$;
