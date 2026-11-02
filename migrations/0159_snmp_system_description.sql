-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Observational SNMP metadata, never an identity or routing selector.
-- lock-ok: nullable metadata-only ADD; existing rows get NULL. NOT VALID
-- avoids a historical scan while the DDL lock is held; new writes are checked.
ALTER TABLE entity_evidence
    ADD COLUMN IF NOT EXISTS snmp_system_description text;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='entity_evidence'::regclass
          AND conname='entity_evidence_snmp_system_description_check') THEN
        ALTER TABLE entity_evidence
            ADD CONSTRAINT entity_evidence_snmp_system_description_check
            CHECK (snmp_system_description IS NULL OR (
                source_kind='device_target' AND alias_kind='address'
                AND source_ref='snmp:configured-target'
                AND octet_length(snmp_system_description) BETWEEN 1 AND 1024
                AND translate(snmp_system_description, E'\t\n\r', '') !~ '[[:cntrl:]]'
            )) NOT VALID;
    END IF;
END $$;
