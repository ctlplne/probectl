-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Complete object manifests follow positive operator byte admission, not an
-- independent reference/population quota. Every encrypted header stays charged.
-- lock-ok: install the replacement NOT VALID before dropping the old ceiling;
-- no historical row scan, body rewrite, tenant or ownership boundary change.
DO $capacity$
DECLARE target record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.flow_snapshots'::regclass
          AND conname='flow_snapshots_private_header_charge') THEN
        ALTER TABLE public.flow_snapshots
            ADD CONSTRAINT flow_snapshots_private_header_charge
            CHECK (octet_length(private_header) > 0
                AND octet_length(private_header) <= charged_bytes) NOT VALID;
    END IF;
    ALTER TABLE public.flow_snapshots
        DROP CONSTRAINT IF EXISTS flow_snapshots_private_header_check;

    -- Fresh copies inherit the public template. Repair existing managed
    -- physical copies too; unrelated/count-only schema doubles are not stores.
    FOR target IN
        SELECT n.nspname
        FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
        WHERE n.nspname ~ '^t_[0-9a-f]{32}$'
          AND c.relname='flow_snapshots' AND c.relkind IN ('r','p')
          AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
              AND a.attname='private_header' AND a.attnum>0 AND NOT a.attisdropped)
          AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
              AND a.attname='charged_bytes' AND a.attnum>0 AND NOT a.attisdropped)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid=format('%I.flow_snapshots',target.nspname)::regclass
              AND conname='flow_snapshots_private_header_charge') THEN
            EXECUTE format('ALTER TABLE %I.flow_snapshots ADD CONSTRAINT flow_snapshots_private_header_charge CHECK (octet_length(private_header)>0 AND octet_length(private_header)<=charged_bytes) NOT VALID',target.nspname);
        END IF;
        EXECUTE format('ALTER TABLE %I.flow_snapshots DROP CONSTRAINT IF EXISTS flow_snapshots_private_header_check',target.nspname);
    END LOOP;
END
$capacity$;
