-- 0127_alert_rules_trap_match.sql
-- D-61: trap-driven alert rules. A rule of type 'trap' matches the tenant's
-- stored SNMP traps (device_traps, 0126) instead of a metric series; its match
-- (trap OID, optional clear-trap OID, device, varbind equality, hold time) is
-- one JSON object in this new column. Expand-only: the column is nullable with
-- no default rewrite, so release N-1 keeps reading and writing every existing
-- rule unchanged (its explicit column lists never name trap_match), and a trap
-- rule seen by N-1 evaluates its fixed probectl_device_trap metric to no data.
-- alert_rules already carries tenant_id NOT NULL + FORCE RLS (0011); a new
-- column inherits the table's row security.

ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS trap_match jsonb;
