-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS bgp_visibility_monitors (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    prefix cidr NOT NULL,
    minimum_visible_basis_points integer NOT NULL CHECK (minimum_visible_basis_points BETWEEN 1 AND 10000),
    alert_on_partial boolean NOT NULL,
    alert_on_loss boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,prefix)
);

-- The raw public archive is shared. Membership of the monitored set and its
-- derived history are private to this tenant, including unavailable points.
CREATE TABLE IF NOT EXISTS bgp_visibility_points (
    tenant_id uuid NOT NULL,
    monitor_id uuid NOT NULL,
    source text NOT NULL CHECK (source ~ '^[a-z][a-z0-9-]{0,31}$'),
    collector text NOT NULL CHECK (collector ~ '^[a-z][a-z0-9.-]{0,63}$'),
    observed_at timestamptz NOT NULL,
    baseline_clock timestamptz NOT NULL,
    archive_clock timestamptz NOT NULL,
    baseline_sha256 bytea NOT NULL CHECK (octet_length(baseline_sha256)=32),
    archive_sha256 bytea NOT NULL CHECK (octet_length(archive_sha256)=32),
    policy_version text NOT NULL CHECK (policy_version ~ '^[a-z0-9][a-z0-9.-]{0,63}$'),
    minimum_peer_routes integer NOT NULL CHECK (minimum_peer_routes>0),
    eligible_peers integer,
    visible_peers integer,
    ambiguous_origin_peers integer,
    origins jsonb,
    availability text NOT NULL CHECK (availability IN ('available','empty_cohort','archive_gap','session_change')),
    PRIMARY KEY (tenant_id,monitor_id,source,collector,observed_at),
    FOREIGN KEY (tenant_id,monitor_id) REFERENCES bgp_visibility_monitors(tenant_id,id) ON DELETE CASCADE,
    CHECK (baseline_clock<=archive_clock AND archive_clock<=observed_at),
    CHECK ((availability='available'
            AND eligible_peers IS NOT NULL AND eligible_peers BETWEEN 1 AND 65535
            AND visible_peers IS NOT NULL AND visible_peers BETWEEN 0 AND eligible_peers
            AND ambiguous_origin_peers IS NOT NULL AND ambiguous_origin_peers BETWEEN 0 AND visible_peers
            AND origins IS NOT NULL AND jsonb_typeof(origins)='array')
        OR (availability<>'available' AND eligible_peers IS NULL AND visible_peers IS NULL
            AND ambiguous_origin_peers IS NULL AND origins IS NULL))
);

CREATE INDEX IF NOT EXISTS bgp_visibility_points_tenant_monitor_clock_idx
    ON bgp_visibility_points(tenant_id,monitor_id,observed_at DESC,source,collector);

ALTER TABLE bgp_visibility_monitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_visibility_monitors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bgp_visibility_monitors;
CREATE POLICY tenant_isolation ON bgp_visibility_monitors
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);

ALTER TABLE bgp_visibility_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_visibility_points FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bgp_visibility_points;
CREATE POLICY tenant_isolation ON bgp_visibility_points
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON bgp_visibility_monitors TO probectl_app;
GRANT SELECT, INSERT, DELETE ON bgp_visibility_points TO probectl_app;

DROP TRIGGER IF EXISTS tenant_write_fence ON public.bgp_visibility_monitors;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON public.bgp_visibility_monitors
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.bgp_visibility_monitors ENABLE ALWAYS TRIGGER tenant_write_fence;

DROP TRIGGER IF EXISTS tenant_write_fence ON public.bgp_visibility_points;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT ON public.bgp_visibility_points
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.bgp_visibility_points ENABLE ALWAYS TRIGGER tenant_write_fence;
