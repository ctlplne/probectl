-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: release the brief metadata lock before online validation.
-- The preceding committed migration retains both replacement unique indexes.
DO $config_legacy$ BEGIN
 PERFORM set_config('lock_timeout','5s',true);
 ALTER TABLE public.device_configs DROP CONSTRAINT IF EXISTS device_configs_tenant_id_device_version_key;
END $config_legacy$;
ALTER TABLE public.device_configs VALIDATE CONSTRAINT device_configs_binding_complete;
ALTER TABLE public.device_configs VALIDATE CONSTRAINT device_configs_binding_device_fk;
