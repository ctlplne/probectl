-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Total selected rows follow resource admission. The integer column itself
-- supplies the representation bound; tenant/owner/generation checks stay intact.
ALTER TABLE public.flow_snapshots DROP CONSTRAINT IF EXISTS flow_snapshots_row_count_check;
ALTER TABLE public.flow_snapshots ADD CONSTRAINT flow_snapshots_row_count_check CHECK (row_count >= 0);

-- Existing physical silo copies predate the expanded pooled constraint. Fresh
-- copies inherit the pooled shape through the existing planner.
DO $capacity$
DECLARE target record;
BEGIN
    FOR target IN
        SELECT n.nspname
        FROM pg_namespace n JOIN pg_class c ON c.relnamespace = n.oid
        WHERE n.nspname ~ '^t_[0-9a-f]{32}$'
          AND c.relname = 'flow_snapshots' AND c.relkind IN ('r','p')
    LOOP
        EXECUTE format('ALTER TABLE %I.flow_snapshots DROP CONSTRAINT IF EXISTS flow_snapshots_row_count_check', target.nspname);
        EXECUTE format('ALTER TABLE %I.flow_snapshots ADD CONSTRAINT flow_snapshots_row_count_check CHECK (row_count >= 0)', target.nspname);
    END LOOP;
END
$capacity$;
