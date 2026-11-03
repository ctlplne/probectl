-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Additive metadata; NULL retains legacy/withheld and '{}' is complete empty.
-- lock-ok: nullable ADD and NOT VALID CHECK do not scan historical evidence.
ALTER TABLE entity_evidence ADD COLUMN IF NOT EXISTS agent_addresses inet[];

CREATE OR REPLACE FUNCTION public.probectl_agent_addresses_valid(addresses inet[])
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
    SELECT CASE WHEN addresses IS NULL THEN true
        WHEN COALESCE(array_ndims(addresses),1)<>1 THEN false
        ELSE array_position(addresses,NULL) IS NULL
        AND octet_length(addresses::text)<=1048576
        AND NOT EXISTS (
            SELECT 1 FROM unnest(addresses) AS u(address) WHERE
                masklen(address)<>CASE family(address) WHEN 4 THEN 32 ELSE 128 END
                OR address IN ('0.0.0.0'::inet,'::'::inet,'255.255.255.255'::inet)
                OR address <<= '224.0.0.0/4'::inet
                OR address <<= 'ff00::/8'::inet
                OR address <<= '::ffff:0:0/96'::inet
        )
    END;
$$;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='entity_evidence'::regclass AND conname='entity_evidence_agent_addresses_check') THEN
        ALTER TABLE entity_evidence ADD CONSTRAINT entity_evidence_agent_addresses_check
            CHECK (agent_addresses IS NULL OR
             (source_kind='agent_site' AND alias_kind='agent_site_id'
              AND configured_ref=agent_id AND source_ref='agent:label:site'
              AND public.probectl_agent_addresses_valid(agent_addresses))) NOT VALID;
    END IF;
END $$;
