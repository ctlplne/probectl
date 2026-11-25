-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Keep the existing tenant-policy and provider lifecycle metadata boundary.
-- A saved legacy row starts at revision zero and stays inert until replaced.
-- lock-ok: nullable domain plus constant revision default avoid a rewrite.
ALTER TABLE tenant_branding ADD COLUMN IF NOT EXISTS brand_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE tenant_branding ADD COLUMN IF NOT EXISTS brand_domain text;

-- Existing rows and rows on the old write path have no active domain.
-- lock-ok: partial index on a newly added nullable column with no existing keys.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_branding_active_domain_idx
    ON tenant_branding (brand_domain) WHERE brand_domain IS NOT NULL;

COMMENT ON TABLE tenant_branding IS
    'Provider-managed customer brand with immutable probectl attribution. Only revisions above zero are active.';
