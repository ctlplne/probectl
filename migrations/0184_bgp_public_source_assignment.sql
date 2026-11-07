-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Public collectors extend the existing operator-owned source assignment;
-- entity evidence keeps its original producer-family checks. No router or
-- BMP selector may supply authority for this public source.
ALTER TABLE entity_source_contexts
    DROP CONSTRAINT IF EXISTS entity_source_contexts_source_kind_check;
ALTER TABLE entity_source_contexts
    ADD CONSTRAINT entity_source_contexts_source_kind_check CHECK (source_kind IN
        ('device_target','flow_exporter','path_agent','bmp_peer','agent_site','public_bgp')) NOT VALID;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='entity_source_contexts'::regclass
                     AND conname='fx5_public_source_shape') THEN
        ALTER TABLE entity_source_contexts ADD CONSTRAINT fx5_public_source_shape
            CHECK (source_kind<>'public_bgp' OR
                   (anchor_entity_id IS NULL AND routing_epoch IS NULL
                    AND routing_assigned_at IS NULL AND routing_bindings IS NULL)) NOT VALID;
    END IF;
END $$;
