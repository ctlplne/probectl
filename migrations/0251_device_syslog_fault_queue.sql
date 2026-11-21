-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS public.device_syslog_fault_queue (
    tenant_id uuid NOT NULL CONSTRAINT device_syslog_fault_tenant_fk
        REFERENCES public.tenants(id) ON DELETE CASCADE,
    event_id uuid NOT NULL,
    target text NOT NULL CHECK (target ~ '^device-syslog:[0-9a-f]{64}$'),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 64),
    observed_at timestamptz NOT NULL,
    incident_id uuid,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT device_syslog_fault_event_fk FOREIGN KEY (tenant_id, event_id)
        REFERENCES public.device_syslog(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS device_syslog_fault_pending
    ON public.device_syslog_fault_queue (tenant_id, observed_at, event_id)
    WHERE incident_id IS NULL;

ALTER TABLE public.device_syslog_fault_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_syslog_fault_queue FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_syslog_fault_tenant ON public.device_syslog_fault_queue;
CREATE POLICY device_syslog_fault_tenant ON public.device_syslog_fault_queue
    USING (tenant_id = nullif(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.device_syslog_fault_queue TO probectl_app;
