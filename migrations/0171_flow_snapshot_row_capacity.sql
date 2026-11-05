-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Total selected rows follow resource admission. The integer column supplies
-- the representation bound; tenant/owner/generation checks stay intact.
-- lock-ok: expand with NOT VALID before dropping only the superseded quota;
-- no historical row scan or body rewrite. New writes enforce nonnegative rows.
DO $capacity$
DECLARE target record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.flow_snapshots'::regclass
          AND conname='flow_snapshots_row_count_nonnegative') THEN
        ALTER TABLE public.flow_snapshots
            ADD CONSTRAINT flow_snapshots_row_count_nonnegative
            CHECK (row_count >= 0) NOT VALID;
    END IF;
    ALTER TABLE public.flow_snapshots
        DROP CONSTRAINT IF EXISTS flow_snapshots_row_count_check;

    -- Existing physical copies need the same expansion; fresh copies inherit
    -- the pooled template through the existing planner.
    FOR target IN
        SELECT n.nspname
        FROM pg_namespace n JOIN pg_class c ON c.relnamespace = n.oid
        WHERE n.nspname ~ '^t_[0-9a-f]{32}$'
          AND c.relname = 'flow_snapshots' AND c.relkind IN ('r','p')
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid=format('%I.flow_snapshots', target.nspname)::regclass
              AND conname='flow_snapshots_row_count_nonnegative') THEN
            EXECUTE format('ALTER TABLE %I.flow_snapshots ADD CONSTRAINT flow_snapshots_row_count_nonnegative CHECK (row_count >= 0) NOT VALID', target.nspname);
        END IF;
        EXECUTE format('ALTER TABLE %I.flow_snapshots DROP CONSTRAINT IF EXISTS flow_snapshots_row_count_check', target.nspname);
    END LOOP;
END
$capacity$;
