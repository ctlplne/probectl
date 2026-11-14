-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Tenant-owned opt-in and pending trigger metadata on the existing schedule.
-- lock-ok: nullable/constant-default additive columns; no table rewrite/scan.
DO $provider_report_triggers$
DECLARE target record;
BEGIN
 FOR target IN SELECT n.nspname FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
 WHERE c.relname='dashboard_report_schedules' AND c.relkind IN ('r','p')
 AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$') LOOP
  EXECUTE format('ALTER TABLE %I.dashboard_report_schedules ADD COLUMN IF NOT EXISTS provider_trigger_allowed boolean NOT NULL DEFAULT false',target.nspname);
  EXECUTE format('ALTER TABLE %I.dashboard_report_schedules ADD COLUMN IF NOT EXISTS provider_request_id uuid',target.nspname);
  EXECUTE format('ALTER TABLE %I.dashboard_report_schedules ADD COLUMN IF NOT EXISTS provider_original_next_run_at timestamptz',target.nspname);
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=format('%I.dashboard_report_schedules',target.nspname)::regclass AND conname='dashboard_report_provider_origin') THEN
   EXECUTE format('ALTER TABLE %I.dashboard_report_schedules ADD CONSTRAINT dashboard_report_provider_origin CHECK ((provider_request_id IS NULL)=(provider_original_next_run_at IS NULL)) NOT VALID',target.nspname);
  END IF;
 END LOOP;
END
$provider_report_triggers$;
