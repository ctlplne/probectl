-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Routing selectors are explicit operator metadata on the existing tenant-owned
-- source assignment. Existing entity planes keep their single-context contract.
-- NULL is the legacy global-only source; a present empty manifest authorizes no
-- routing views. An opaque epoch changes with the complete operator assignment,
-- so a former source generation can never borrow a replacement binding.
ALTER TABLE entity_source_contexts
    ADD COLUMN IF NOT EXISTS routing_epoch uuid,
    ADD COLUMN IF NOT EXISTS routing_assigned_at timestamptz,
    ADD COLUMN IF NOT EXISTS routing_bindings jsonb;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='entity_source_contexts'::regclass
                     AND conname='entity_source_routing_manifest_shape') THEN
        ALTER TABLE entity_source_contexts
            ADD CONSTRAINT entity_source_routing_manifest_shape CHECK (
                (routing_epoch IS NULL AND routing_bindings IS NULL AND routing_assigned_at IS NULL)
                OR (source_kind='bmp_peer' AND routing_epoch IS NOT NULL
                    AND routing_epoch<>'00000000-0000-0000-0000-000000000000'::uuid
                    AND routing_bindings IS NOT NULL AND routing_assigned_at IS NOT NULL
                    AND jsonb_typeof(routing_bindings)='array'));
    END IF;
END $$;
