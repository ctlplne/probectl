-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS bmp_session_evidence (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    router_id uuid NOT NULL,
    collector_agent_id text NOT NULL CHECK (octet_length(collector_agent_id) BETWEEN 1 AND 1024),
    source_ref text NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    sender_serial text NOT NULL,
    origin_serial text NOT NULL,
    source_epoch uuid,
    connection_id uuid NOT NULL,
    source_sequence bigint NOT NULL CHECK (source_sequence > 0),
    observed_at timestamptz NOT NULL,
    observed_unix_nanos bigint NOT NULL CHECK (observed_unix_nanos > 0),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    evidence_kind text NOT NULL CHECK (evidence_kind IN ('statistics', 'neighbor', 'update_churn', 'initiation', 'termination', 'transport_closed')),
    coverage_gap boolean NOT NULL,
    peer_addr inet,
    peer_asn bigint CHECK (peer_asn BETWEEN 1 AND 4294967295),
    peer_bgp_id inet,
    loss_confirmed boolean NOT NULL,
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    PRIMARY KEY (tenant_id, collector_agent_id, source_ref, connection_id, source_sequence)
);

CREATE INDEX IF NOT EXISTS bmp_session_evidence_history_idx
    ON bmp_session_evidence (tenant_id, context_id, router_id, collector_agent_id, source_ref,
        observed_unix_nanos DESC, connection_id DESC, source_sequence DESC);

CREATE INDEX IF NOT EXISTS bmp_session_evidence_gap_idx
    ON bmp_session_evidence (tenant_id, collector_agent_id, source_ref, connection_id, source_sequence DESC)
    WHERE coverage_gap;

CREATE INDEX IF NOT EXISTS bmp_session_evidence_peer_event_idx
    ON bmp_session_evidence (tenant_id, collector_agent_id, source_ref, connection_id,
        peer_addr, peer_asn, peer_bgp_id, source_sequence DESC)
    WHERE evidence_kind = 'neighbor';

CREATE INDEX IF NOT EXISTS bmp_session_evidence_loss_idx
    ON bmp_session_evidence (tenant_id, collector_agent_id, source_ref, connection_id,
        peer_addr, peer_asn, peer_bgp_id, observed_unix_nanos DESC, source_sequence)
    WHERE loss_confirmed;

ALTER TABLE bmp_session_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE bmp_session_evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bmp_session_evidence;
CREATE POLICY tenant_isolation ON bmp_session_evidence
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, DELETE ON bmp_session_evidence TO probectl_app;
DROP TRIGGER IF EXISTS tenant_write_fence ON public.bmp_session_evidence;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT ON public.bmp_session_evidence
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.bmp_session_evidence ENABLE ALWAYS TRIGGER tenant_write_fence;
