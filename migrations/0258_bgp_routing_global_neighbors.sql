-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A current routing target may retain a post-policy neighbor view only for
-- the authenticated BMP source's own global base router and context.
-- The validated predecessor already implies this expanded predicate for all
-- existing rows. Check new writes without scanning the live routing table.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx11_route_view_routing_selection_check') THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx11_route_view_routing_selection_check CHECK ((
            (routing_selection IS NULL AND view_kind<>'operator_loc_rib') OR
            (routing_selection IS NOT NULL AND source_kind='router_bmp'
             AND (view_kind='operator_loc_rib' OR (view_kind='adj_rib_in_post_policy'
                  AND peer_identity->>'Type'='0'
                  AND routing_selection->>'base_context_id'=context_id::text
                  AND routing_selection->>'base_router_id'=router_id::text
                  AND routing_selection->'binding'->>'distinguisher'='0000000000000000'))
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
ALTER TABLE bgp_routing_views DROP CONSTRAINT IF EXISTS fx5_route_view_routing_selection_check;
