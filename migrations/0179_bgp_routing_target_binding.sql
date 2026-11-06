-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The collector keeps its original entity context. An explicitly configured
-- routing target can belong to another owned VRF without changing that grant.
-- Old readers only recognize loc_rib; operator_loc_rib requires the complete
-- current binding check and cannot be consumed as a legacy unbound view.
ALTER TABLE bgp_routing_views
    ADD COLUMN IF NOT EXISTS routing_selection jsonb;
ALTER TABLE bgp_routing_views
    ADD COLUMN IF NOT EXISTS collector_context_id uuid GENERATED ALWAYS AS
        (COALESCE((routing_selection->>'base_context_id')::uuid,context_id)) STORED;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx5_route_view_collector_context_fk') THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_route_view_collector_context_fk
            FOREIGN KEY (tenant_id,collector_agent_id,collector_context_id)
            REFERENCES entity_agent_contexts(tenant_id,agent_id,context_id) ON DELETE CASCADE;
    END IF;
END $$;
-- The replacement FK enforces the same legacy assignment and the explicit
-- bound base assignment before the original target-context FK is retired.
ALTER TABLE bgp_routing_views DROP CONSTRAINT IF EXISTS fx5_route_view_agent_context_fk;
ALTER TABLE bgp_routing_views DROP CONSTRAINT IF EXISTS bgp_routing_views_view_kind_check;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx5_route_view_kind_check') THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_route_view_kind_check CHECK (view_kind IN (
            'adj_rib_in_pre_policy','adj_rib_in_post_policy','adj_rib_out_pre_policy',
            'adj_rib_out_post_policy','loc_rib','operator_loc_rib','public_bgp')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx5_route_view_routing_selection_check') THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_route_view_routing_selection_check CHECK ((
            (routing_selection IS NULL AND view_kind<>'operator_loc_rib') OR
            (routing_selection IS NOT NULL AND source_kind='router_bmp' AND view_kind='operator_loc_rib'
             AND jsonb_typeof(routing_selection)='object'
             AND routing_selection ?& ARRAY['base_context_id','base_router_id','context_id','router_id',
                                            'epoch','binding_id','assigned_at','families','binding']
             AND routing_selection->>'base_context_id' IS NOT NULL
             AND routing_selection->>'context_id'=context_id::text
             AND routing_selection->>'router_id'=router_id::text
             AND jsonb_typeof(routing_selection->'binding')='object'
             AND jsonb_typeof(routing_selection->'families')='array')) IS TRUE) NOT VALID;
    END IF;
END $$;
ALTER TABLE bgp_routing_views VALIDATE CONSTRAINT fx5_route_view_kind_check;
ALTER TABLE bgp_routing_views VALIDATE CONSTRAINT fx5_route_view_routing_selection_check;
