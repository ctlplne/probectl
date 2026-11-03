// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// Old LIKE copies retain the original whole-rule shape CHECK. Replace just
// that CHECK atomically, without scanning history or dropping ownership FKs.
func tagRuleMatchConstraintPlan(schema string) []string {
	child := quoteIdent(schema) + `."tenant_tag_rules"`
	const name = "tenant_tag_rules_match_v2_check"
	return []string{fmt.Sprintf(`DO $tag_match_silo$
DECLARE old_check record;
BEGIN
    FOR old_check IN SELECT conname FROM pg_constraint
        WHERE conrelid=%s::regclass AND contype='c' AND conname<>%s
          AND pg_get_constraintdef(oid) LIKE '%%match_kind%%'
          AND pg_get_constraintdef(oid) LIKE '%%address_side%%'
          AND pg_get_constraintdef(oid) LIKE '%%snmp_value%%'
    LOOP
        EXECUTE format('ALTER TABLE %%s DROP CONSTRAINT %%I', %s, old_check.conname);
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
        ALTER TABLE %s ADD CONSTRAINT %s CHECK (
            (match_kind='cidr' AND address_side IS NOT NULL AND address_side IN
              ('src','dst','exporter','interface','device') AND cidr IS NOT NULL
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
$tag_match_silo$`, quoteLiteral(child), quoteLiteral(name), quoteLiteral(child),
		quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name))}
}
