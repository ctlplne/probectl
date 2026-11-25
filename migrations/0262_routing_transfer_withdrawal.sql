-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- lock-ok: add a nullable marker and metadata-only constraint. Keep the
-- immutable approval and rollback in the original tenant proposal row.
CREATE OR REPLACE FUNCTION public.probectl_install_routing_transfer_withdrawal(schema_name text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass;
BEGIN
    IF schema_name IS NULL OR (schema_name<>'public' AND schema_name !~ '^t_[0-9a-f]{32}$') THEN
        RAISE EXCEPTION 'invalid managed routing transfer schema';
    END IF;
    target=to_regclass(format('%I.remediation_proposals',schema_name));
    IF target IS NULL OR NOT EXISTS (SELECT 1 FROM pg_attribute
        WHERE attrelid=target AND attname='routing_transfer_approval' AND NOT attisdropped) THEN RETURN; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS routing_transfer_withdraw_requested_at timestamptz',target);
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=target
        AND conname='remediation_proposals_routing_transfer_withdrawal_v1') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT remediation_proposals_routing_transfer_withdrawal_v1 CHECK (
            routing_transfer_withdraw_requested_at IS NULL OR (
                kind=''routing_transfer_review'' AND state=''approved'' AND routing_transfer_approval IS NOT NULL
                AND decided_at IS NOT NULL AND routing_transfer_withdraw_requested_at>=decided_at
            )) NOT VALID',target);
    END IF;
END;
$$;

DO $routing_transfer_withdrawal$
DECLARE managed text;
BEGIN
    FOR managed IN SELECT nspname FROM pg_namespace
        WHERE nspname='public' OR nspname ~ '^t_[0-9a-f]{32}$'
    LOOP
        PERFORM public.probectl_install_routing_transfer_withdrawal(managed);
    END LOOP;
END;
$routing_transfer_withdrawal$;
