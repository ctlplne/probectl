-- SPDX-License-Identifier: BUSL-1.1
--
-- Operator-supplied placement labels are authoritative local metadata for the
-- owned-vantage coverage cockpit. They arrive on the authenticated agent
-- registration channel; no IP geolocation or other external lookup is used.
--
-- tenant_id + forced RLS already protect agents from its first migration.
-- This additive JSON object is bounded and validated by the registration
-- service before persistence.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS labels jsonb NOT NULL DEFAULT '{}'::jsonb;
