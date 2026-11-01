-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2: correlation identity is a verified tenant/context/entity tuple, held
-- beside both the incident and its original signal. A null context marks a
-- legacy/unbound signal; a context with null entity is a deletion tombstone
-- that must never return to raw private-address correlation.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS entity_context_id uuid,
    ADD COLUMN IF NOT EXISTS entity_id uuid,
    ADD COLUMN IF NOT EXISTS identity_lookup_attempted boolean NOT NULL DEFAULT false;
ALTER TABLE incident_signals
    ADD COLUMN IF NOT EXISTS entity_context_id uuid,
    ADD COLUMN IF NOT EXISTS entity_id uuid,
    ADD COLUMN IF NOT EXISTS identity_lookup_attempted boolean NOT NULL DEFAULT false;
ALTER TABLE incident_correlation_overrides
    ADD COLUMN IF NOT EXISTS entity_context_id uuid,
    ADD COLUMN IF NOT EXISTS entity_id uuid,
    ADD COLUMN IF NOT EXISTS identity_lookup_attempted boolean NOT NULL DEFAULT false;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incidents'::regclass
                     AND conname='incidents_entity_pair_ck') THEN
        ALTER TABLE incidents ADD CONSTRAINT incidents_entity_pair_ck
            CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_signals'::regclass
                     AND conname='incident_signals_entity_pair_ck') THEN
        ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_entity_pair_ck
            CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incidents'::regclass
                     AND conname='incidents_identity_lookup_ck') THEN
        ALTER TABLE incidents ADD CONSTRAINT incidents_identity_lookup_ck
            CHECK (entity_context_id IS NULL OR identity_lookup_attempted);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_signals'::regclass
                     AND conname='incident_signals_identity_lookup_ck') THEN
        ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_identity_lookup_ck
            CHECK (entity_context_id IS NULL OR identity_lookup_attempted);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_correlation_overrides'::regclass
                     AND conname='incident_overrides_entity_pair_ck') THEN
        ALTER TABLE incident_correlation_overrides ADD CONSTRAINT incident_overrides_entity_pair_ck
            CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_correlation_overrides'::regclass
                     AND conname='incident_overrides_identity_lookup_ck') THEN
        ALTER TABLE incident_correlation_overrides ADD CONSTRAINT incident_overrides_identity_lookup_ck
            CHECK (entity_context_id IS NULL OR identity_lookup_attempted);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incidents'::regclass
                     AND conname='incidents_entity_fk') THEN
        ALTER TABLE incidents ADD CONSTRAINT incidents_entity_fk
            FOREIGN KEY (tenant_id,entity_context_id,entity_id)
            REFERENCES entities(tenant_id,context_id,id)
            ON DELETE SET NULL (entity_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_signals'::regclass
                     AND conname='incident_signals_entity_fk') THEN
        ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_entity_fk
            FOREIGN KEY (tenant_id,entity_context_id,entity_id)
            REFERENCES entities(tenant_id,context_id,id)
            ON DELETE SET NULL (entity_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_correlation_overrides'::regclass
                     AND conname='incident_overrides_entity_fk') THEN
        ALTER TABLE incident_correlation_overrides ADD CONSTRAINT incident_overrides_entity_fk
            FOREIGN KEY (tenant_id,entity_context_id,entity_id)
            REFERENCES entities(tenant_id,context_id,id)
            ON DELETE SET NULL (entity_id);
    END IF;
    -- The original FK named only incident_id. This compound FK also prevents
    -- a tenant-owned signal row from pointing at another tenant's incident.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='incident_signals'::regclass
                     AND conname='incident_signals_tenant_incident_fk') THEN
        ALTER TABLE incident_signals ADD CONSTRAINT incident_signals_tenant_incident_fk
            FOREIGN KEY (tenant_id,incident_id)
            REFERENCES incidents(tenant_id,id) ON DELETE CASCADE;
    END IF;
END $$;
