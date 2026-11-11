-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Cache generations are not counter-data erasures. Mark an actual erasure
-- explicitly, preserving the replay floor through its entire transition.
-- Expand every existing owned trigger target before replacing the shared
-- function, so an older running silo cannot see a missing NEW column.
DO $counter_erasure_expand$
DECLARE owned record;
BEGIN
    FOR owned IN
        SELECT c.oid,n.nspname
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE c.relname='flow_snapshot_epochs' AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR EXISTS (
               SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid
                 AND t.tgfoid='public.probectl_source_observation_fence()'::regprocedure
                 AND NOT t.tgisinternal))
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=owned.oid
                       AND attname='observation_erasing' AND attnum>0 AND NOT attisdropped) THEN
            EXECUTE format('ALTER TABLE %I.flow_snapshot_epochs ADD COLUMN observation_erasing boolean NOT NULL DEFAULT false',owned.nspname);
            -- An upgrade cannot distinguish an already pending old erasure
            -- from old cache maintenance. Preserve the conservative fence
            -- once; subsequent cache-only transitions never set this marker.
            EXECUTE format('UPDATE %I.flow_snapshot_epochs SET observation_erasing=true WHERE invalidating',owned.nspname);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=owned.oid
                       AND conname='counter_observation_erasure_shape') THEN
            EXECUTE format('ALTER TABLE %I.flow_snapshot_epochs ADD CONSTRAINT counter_observation_erasure_shape CHECK (NOT observation_erasing OR invalidating)',owned.nspname);
        END IF;
    END LOOP;
END; $counter_erasure_expand$;

CREATE OR REPLACE FUNCTION public.probectl_source_observation_fence()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        -- The previous application version requests subject erasure with
        -- INSERT ... invalidating=true ON CONFLICT DO UPDATE. Preserve that
        -- request even though its conflict clause does not yet set the new
        -- column. Cache maintenance uses UPDATE after a false/default INSERT.
        -- Markers are local to this transaction and exact tenant/token pair.
        IF NEW.invalidating THEN
            NEW.observation_erasing=true;
            PERFORM set_config('probectl.source_erasure_tenant',NEW.tenant_id::text,true);
            PERFORM set_config('probectl.source_erasure_token',COALESCE(NEW.transition_token::text,''),true);
        END IF;
        IF NEW.observation_erasing THEN
            NEW.observation_not_before=GREATEST(NEW.observation_not_before,clock_timestamp());
        END IF;
        RETURN NEW;
    END IF;
    -- Neither cache generations nor a legacy catch-up backfill may advance
    -- or lower the data-erasure clock. Only actual erasure transitions do so.
    NEW.observation_not_before=OLD.observation_not_before;
    IF NEW.invalidating
       AND current_setting('probectl.source_erasure_tenant',true)=NEW.tenant_id::text
       AND current_setting('probectl.source_erasure_token',true)=COALESCE(NEW.transition_token::text,'') THEN
        NEW.observation_erasing=true;
    END IF;
    IF NEW.observation_erasing AND NOT OLD.observation_erasing THEN
        NEW.observation_not_before=GREATEST(NEW.observation_not_before,clock_timestamp());
    END IF;
    IF OLD.observation_erasing THEN
        IF NOT NEW.invalidating THEN
            NEW.observation_not_before=GREATEST(NEW.observation_not_before,clock_timestamp());
            NEW.observation_erasing=false;
        ELSE
            -- A partial/retried erasure cannot clear its marker early.
            NEW.observation_erasing=true;
        END IF;
    END IF;
    RETURN NEW;
END; $$;
