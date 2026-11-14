-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Repair version-2-only checks restored by the old silo catch-up after0208.
-- Version6 already preserves every body/digest/tenant/format constraint.
-- lock-ok: drop a superseded check only when its compatible replacement exists.
DO $monthly_silo_catchup$
DECLARE target record;
BEGIN
 FOR target IN SELECT n.nspname FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
 WHERE c.relname='dashboard_report_artifacts' AND c.relkind IN ('r','p')
 AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$') LOOP
  IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=format('%I.dashboard_report_artifacts',target.nspname)::regclass AND conname='dashboard_report_artifacts_body_representation_v6') THEN
   EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation_v5',target.nspname);
  END IF;
 END LOOP;
END
$monthly_silo_catchup$;
