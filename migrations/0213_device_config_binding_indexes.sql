-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: build replacement archive access paths without blocking writers.
-- Existing physical silos build their own copies in online schema catch-up.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS device_configs_bound_stream_version_idx
 ON public.device_configs (tenant_id,entity_context_id,device_entity_id,binding_agent_id,binding_source_ref,binding_source_assigned_at,binding_agent_assigned_at,version)
 WHERE entity_context_id IS NOT NULL;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS device_configs_legacy_stream_version_idx
 ON public.device_configs (tenant_id,device,version) WHERE entity_context_id IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS device_configs_bound_observed_idx
 ON public.device_configs (tenant_id,entity_context_id,device_entity_id,binding_agent_id,binding_source_ref,observed_at DESC,id) WHERE entity_context_id IS NOT NULL;
