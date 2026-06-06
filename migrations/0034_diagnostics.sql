-- 0034: Supportability (S-EE4, F35) — the diagnostics.read permission.
--
-- The deep-health report (/v1/diagnostics) and the secret-stripped support
-- bundle (/v1/diagnostics/bundle) are admin operations: they expose
-- operational diagnostics (redacted config, deep health, anonymized topology).
-- The bundle never contains secrets/credentials/PII (guardrail 6), but it is
-- still operator-only. Admin-seeded, like fairness.read (0031) /
-- governance.read (0033).
--
-- Idempotent + expand-only (CLAUDE.md §6).

INSERT INTO permissions (key, description) VALUES
    ('diagnostics.read', 'Read deep health + generate the secret-stripped support bundle')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'diagnostics.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;
