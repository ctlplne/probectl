-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Nullable metadata only: legacy archives stay unbound and remain writable.
-- Separate blocks keep additive columns independent from staged constraints.
SET LOCAL lock_timeout='5s';
DO $config_columns$
DECLARE target record;
BEGIN
 FOR target IN SELECT n.nspname FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid WHERE c.relname='device_configs' AND c.relkind IN ('r','p') AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$') LOOP
  EXECUTE format('ALTER TABLE %I.device_configs
   ADD COLUMN IF NOT EXISTS entity_context_id uuid,
   ADD COLUMN IF NOT EXISTS device_entity_id uuid,
   ADD COLUMN IF NOT EXISTS binding_agent_id text,
   ADD COLUMN IF NOT EXISTS binding_source_ref text,
   ADD COLUMN IF NOT EXISTS binding_source_assigned_at timestamptz,
   ADD COLUMN IF NOT EXISTS binding_agent_assigned_at timestamptz,
   ADD COLUMN IF NOT EXISTS bound_at timestamptz',target.nspname);
 END LOOP;
END $config_columns$;

DO $config_constraints$
DECLARE target record;
BEGIN
 FOR target IN SELECT n.nspname FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid WHERE c.relname='device_configs' AND c.relkind IN ('r','p') AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$') LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=format('%I.device_configs',target.nspname)::regclass AND conname='device_configs_binding_complete') THEN
   EXECUTE format('ALTER TABLE %I.device_configs ADD CONSTRAINT device_configs_binding_complete CHECK (
    (entity_context_id IS NULL AND device_entity_id IS NULL AND binding_agent_id IS NULL AND binding_source_ref IS NULL AND binding_source_assigned_at IS NULL AND binding_agent_assigned_at IS NULL AND bound_at IS NULL)
    OR (entity_context_id IS NOT NULL AND device_entity_id IS NOT NULL AND binding_agent_id IS NOT NULL AND binding_source_ref IS NOT NULL AND binding_source_assigned_at IS NOT NULL AND binding_agent_assigned_at IS NOT NULL AND bound_at IS NOT NULL
     AND octet_length(binding_agent_id) BETWEEN 1 AND 128 AND octet_length(binding_source_ref) BETWEEN 1 AND 1024
     AND bound_at>=binding_source_assigned_at AND bound_at>=binding_agent_assigned_at
     AND observed_at>=binding_source_assigned_at AND observed_at>=binding_agent_assigned_at AND observed_at<=bound_at)) NOT VALID',target.nspname);
  END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=format('%I.device_configs',target.nspname)::regclass AND conname='device_configs_binding_device_fk') THEN
   EXECUTE format('ALTER TABLE %I.device_configs ADD CONSTRAINT device_configs_binding_device_fk FOREIGN KEY(tenant_id,entity_context_id,device_entity_id) REFERENCES %I.entities(tenant_id,context_id,id) ON DELETE CASCADE NOT VALID',target.nspname,target.nspname);
  END IF;
 END LOOP;
END $config_constraints$;
