-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Raw observational bytes are independent of normalized identity aliases.
-- NULL is legacy absence; an empty non-NULL value explicitly clears sysName.
-- lock-ok: nullable metadata-only ADD; NOT VALID avoids a historical scan
-- while holding the DDL lock, and the CHECK applies to every new write.
ALTER TABLE entity_evidence
    ADD COLUMN IF NOT EXISTS snmp_system_name text;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='entity_evidence'::regclass
          AND conname='entity_evidence_snmp_system_name_check') THEN
        ALTER TABLE entity_evidence
            ADD CONSTRAINT entity_evidence_snmp_system_name_check
            CHECK (snmp_system_name IS NULL OR (
                source_kind='device_target' AND alias_kind='address'
                AND source_ref='snmp:configured-target'
                AND octet_length(snmp_system_name) <= 1024
                AND snmp_system_name !~ '[[:cntrl:]]'
            )) NOT VALID;
    END IF;
END $$;
