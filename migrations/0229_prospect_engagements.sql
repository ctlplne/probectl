-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS prospect_engagements (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    tenant_slug text NOT NULL CHECK (tenant_slug <> ''),
    owner_id uuid NOT NULL,
    assessment_view_id text NOT NULL CHECK (assessment_view_id <> ''),
    assessment_view_revision timestamptz NOT NULL,
    preparer text NOT NULL CHECK (preparer <> ''),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
    converted_at timestamptz,
    consented_at timestamptz,
    consent_revision bigint,
    consent_destination_id text,
    consent_revoked_at timestamptz,
    CHECK ((consented_at IS NULL AND consent_revision IS NULL AND consent_destination_id IS NULL AND consent_revoked_at IS NULL)
        OR (consented_at IS NOT NULL AND consent_revision IS NOT NULL AND consent_revision > 0
            AND consent_revision <= revision AND consent_destination_id IS NOT NULL
            AND consent_destination_id <> '')),
    CHECK (consent_revoked_at IS NULL OR consent_revoked_at >= consented_at)
);

ALTER TABLE prospect_engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE prospect_engagements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON prospect_engagements;
CREATE POLICY tenant_isolation ON prospect_engagements
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON prospect_engagements TO probectl_app;
