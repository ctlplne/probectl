-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- lock-ok: canonical subject-side CHECK expansion, no row rewrite or historical scan.
-- Preserve every ownership FK/RLS policy and the existing other match shapes.
DO $tag_cidr_facts$
DECLARE old_check record;
BEGIN
    FOR old_check IN SELECT conname FROM pg_constraint
        WHERE conrelid='tenant_tag_rules'::regclass AND contype='c'
          AND conname <> 'tenant_tag_rules_match_v3_check'
          AND pg_get_constraintdef(oid) LIKE '%match_kind%'
          AND pg_get_constraintdef(oid) LIKE '%address_side%'
          AND pg_get_constraintdef(oid) LIKE '%snmp_value%'
    LOOP
        EXECUTE format('ALTER TABLE tenant_tag_rules DROP CONSTRAINT %I', old_check.conname);
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='tenant_tag_rules'::regclass
          AND conname='tenant_tag_rules_match_v3_check') THEN
        ALTER TABLE tenant_tag_rules ADD CONSTRAINT tenant_tag_rules_match_v3_check CHECK (
            (match_kind='cidr' AND address_side IS NOT NULL AND address_side IN
              ('src','dst','exporter','interface','device','agent','test','prefix') AND cidr IS NOT NULL
              AND name_pattern IS NULL AND snmp_field IS NULL AND snmp_value IS NULL) OR
            (match_kind='name_pattern' AND name_pattern IS NOT NULL
              AND octet_length(name_pattern) BETWEEN 1 AND 256
              AND address_side IS NULL AND cidr IS NULL
              AND snmp_field IS NULL AND snmp_value IS NULL) OR
            (match_kind='snmp_field' AND snmp_field IS NOT NULL AND snmp_field IN
              ('sys_name','sys_descr','if_name','if_descr')
              AND snmp_value IS NOT NULL AND octet_length(snmp_value) BETWEEN 1 AND 1024
              AND snmp_value !~ U&'[\007F-\009F]'
              AND CASE WHEN snmp_field='sys_descr'
                  THEN translate(snmp_value, E'\t\n\r', '') !~ '[[:cntrl:]]'
                  ELSE snmp_value !~ '[[:cntrl:]]' END
              AND address_side IS NULL AND cidr IS NULL AND name_pattern IS NULL)
        ) NOT VALID;
    END IF;
END;
$tag_cidr_facts$;
