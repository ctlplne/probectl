-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Existing report artifacts retain retry state. Bodies/digests remain immutable;
-- the app gets column-specific updates only, with existing FORCE-RLS/write fences.
-- lock-ok: additive nullable/constant columns and NOT VALID checks; no rewrite.
DO $report_email$
DECLARE target record;
BEGIN
 FOR target IN SELECT n.nspname FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
 WHERE c.relname='dashboard_report_artifacts' AND c.relkind IN ('r','p')
 AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$') LOOP
  EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts ADD COLUMN IF NOT EXISTS email_destination_id text,ADD COLUMN IF NOT EXISTS email_state text,ADD COLUMN IF NOT EXISTS email_next_attempt_at timestamptz,ADD COLUMN IF NOT EXISTS email_attempts bigint NOT NULL DEFAULT 0,ADD COLUMN IF NOT EXISTS email_delivered_at timestamptz',target.nspname);
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=format('%I.dashboard_report_artifacts',target.nspname)::regclass AND conname='dashboard_report_email_state') THEN
   EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts ADD CONSTRAINT dashboard_report_email_state CHECK ((email_destination_id IS NULL AND email_state IS NULL) OR (email_destination_id IS NOT NULL AND email_state IS NOT NULL AND email_state IN (''pending'',''sent'',''withdrawn'')) AND email_attempts>=0) NOT VALID',target.nspname);
  END IF;
  EXECUTE format('GRANT UPDATE(email_destination_id,email_state,email_next_attempt_at,email_attempts,email_delivered_at) ON %I.dashboard_report_artifacts TO probectl_app',target.nspname);
  EXECUTE format('ALTER TABLE %I.dashboard_report_schedules DROP CONSTRAINT IF EXISTS dashboard_report_schedules_destination_id_check',target.nspname);
 END LOOP;
END
$report_email$;
