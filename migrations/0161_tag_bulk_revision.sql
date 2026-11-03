-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Deduplicate tenant identities before evaluating volatile timestamps. The
-- previous DISTINCT included clock_timestamp(), allowing one bulk statement to
-- target the same revision row twice. Existing pooled and silo triggers both
-- call this function; no table rewrite or trigger replacement is needed.
CREATE OR REPLACE FUNCTION public.tenant_tags_bump_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        EXECUTE format('INSERT INTO %I.tenant_tag_revisions(tenant_id,revision,changed_at) SELECT tenant_id,2,clock_timestamp() FROM (SELECT DISTINCT tenant_id FROM tag_new_rows) changed ON CONFLICT (tenant_id) DO UPDATE SET revision=tenant_tag_revisions.revision+1,changed_at=clock_timestamp()',
                       TG_TABLE_SCHEMA);
    ELSIF TG_OP = 'UPDATE' THEN
        EXECUTE format('UPDATE %I.tenant_tag_revisions r SET revision=r.revision+1,changed_at=clock_timestamp() FROM (SELECT DISTINCT tenant_id FROM tag_new_rows) changed WHERE r.tenant_id=changed.tenant_id',
                       TG_TABLE_SCHEMA);
    ELSE
        -- Tenant deletion must not recreate the deleted parent's revision.
        EXECUTE format('UPDATE %I.tenant_tag_revisions r SET revision=r.revision+1,changed_at=clock_timestamp() FROM (SELECT DISTINCT tenant_id FROM tag_old_rows) changed WHERE r.tenant_id=changed.tenant_id',
                       TG_TABLE_SCHEMA);
    END IF;
    RETURN NULL;
END $$;
