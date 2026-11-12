-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Several test definitions may share a destination in the SAME context.
-- A shared anchor preserves tenant+destination -> one context with a foreign
-- key. It grants no trace, sender or historical observation new authority.
CREATE OR REPLACE FUNCTION public.probectl_path_target_context_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected_context uuid;
BEGIN
    IF TG_TABLE_NAME<>'entity_path_test_contexts' OR TG_TABLE_SCHEMA !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported path binding relation' USING ERRCODE='23514';
    END IF;
    EXECUTE format('INSERT INTO %I.entity_path_targets AS target(tenant_id,path_target,context_id)
        VALUES($1,$2,$3) ON CONFLICT(tenant_id,path_target) DO UPDATE SET context_id=EXCLUDED.context_id
        WHERE target.context_id=EXCLUDED.context_id OR NOT EXISTS (
            SELECT 1 FROM %I.entity_path_test_contexts existing
            WHERE existing.tenant_id=$1 AND existing.path_target=$2 AND existing.test_id<>$4)
        RETURNING context_id',TG_TABLE_SCHEMA,TG_TABLE_SCHEMA)
        INTO selected_context USING NEW.tenant_id,NEW.path_target,NEW.context_id,NEW.test_id;
    IF selected_context IS NULL THEN
        RAISE EXCEPTION 'destination is already assigned to another routing context'
            USING ERRCODE='23505',CONSTRAINT='entity_path_target_one_context';
    END IF;
    IF TG_OP='UPDATE' AND ROW(NEW.tenant_id,NEW.test_id,NEW.context_id,NEW.path_target)
       IS DISTINCT FROM ROW(OLD.tenant_id,OLD.test_id,OLD.context_id,OLD.path_target) THEN
        NEW.assigned_at=clock_timestamp();
    END IF;
    RETURN NEW;
END $$;

-- NO ACTION on the child FK prevents cleanup from cascading away a concurrent
-- new test binding. A conflicting transaction retries, with no partial delete.
CREATE OR REPLACE FUNCTION public.probectl_path_target_context_cleanup()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_TABLE_NAME<>'entity_path_test_contexts' OR TG_TABLE_SCHEMA !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported path binding relation' USING ERRCODE='23514';
    END IF;
    EXECUTE format('DELETE FROM %I.entity_path_targets target
        WHERE target.tenant_id=$1 AND target.path_target=$2 AND NOT EXISTS (
            SELECT 1 FROM %I.entity_path_test_contexts current_binding
            WHERE current_binding.tenant_id=$1 AND current_binding.path_target=$2)',
        TG_TABLE_SCHEMA,TG_TABLE_SCHEMA) USING OLD.tenant_id,OLD.path_target;
    RETURN NULL;
END $$;

-- Invoker installer for migration and managed-silo provisioning. It grants no
-- elevated function rights: callers still need the existing DDL privileges.
CREATE OR REPLACE FUNCTION public.probectl_install_path_target_contexts(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE parent_table text; child_table text; context_table text;
        parent_oid regclass; child_oid regclass; tenant_text text;
        permission record; recipient text; mismatched boolean;
        expected record; actual record; child_columns smallint[]; parent_columns smallint[];
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported path binding schema' USING ERRCODE='23514';
    END IF;
    parent_table=format('%I.entity_path_targets',target_schema);
    child_table=format('%I.entity_path_test_contexts',target_schema);
    context_table=format('%I.entity_contexts',target_schema);
    child_oid=to_regclass(child_table);
    IF child_oid IS NULL OR to_regclass(context_table) IS NULL THEN
        RAISE EXCEPTION 'canonical path binding tables are missing' USING ERRCODE='23514';
    END IF;
    EXECUTE format('CREATE TABLE IF NOT EXISTS %s (
        tenant_id uuid NOT NULL,
        path_target text NOT NULL CHECK(octet_length(path_target) BETWEEN 1 AND 1024),
        context_id uuid NOT NULL,
        PRIMARY KEY(tenant_id,path_target),UNIQUE(tenant_id,path_target,context_id))',parent_table);
    parent_oid=to_regclass(parent_table);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=parent_oid AND conname='entity_path_targets_tenant_fk') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_path_targets_tenant_fk
            FOREIGN KEY(tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE NOT VALID',parent_table);
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=parent_oid AND conname='entity_path_targets_context_fk') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_path_targets_context_fk
            FOREIGN KEY(tenant_id,context_id) REFERENCES %s(tenant_id,id) ON DELETE CASCADE NOT VALID',parent_table,context_table);
    END IF;
    IF target_schema<>'public' THEN
        tenant_text=substring(target_schema,3,8)||'-'||substring(target_schema,11,4)||'-'||
            substring(target_schema,15,4)||'-'||substring(target_schema,19,4)||'-'||substring(target_schema,23,12);
        IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=parent_oid AND conname='entity_path_targets_silo_tenant_check') THEN
            EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_path_targets_silo_tenant_check
                CHECK(tenant_id=%L::uuid) NOT VALID',parent_table,tenant_text);
        END IF;
        EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT entity_path_targets_silo_tenant_check',parent_table);
    END IF;
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',parent_table);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',parent_table);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %s',parent_table);
    EXECUTE format('CREATE POLICY tenant_isolation ON %s
            USING(tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)
            WITH CHECK(tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)',parent_table);
    -- Mirror existing table ACLs, preserving FORCE-RLS on every runtime write.
    FOR permission IN SELECT CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END grantee,
            acl.privilege_type
        FROM pg_class relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) acl
        WHERE relation.oid=child_oid AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE','REFERENCES')
    LOOP
        recipient=CASE WHEN permission.grantee='PUBLIC' THEN 'PUBLIC' ELSE quote_ident(permission.grantee) END;
        EXECUTE format('GRANT %s ON TABLE %s TO %s',permission.privilege_type,parent_table,recipient);
    END LOOP;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %s GROUP BY tenant_id,path_target
        HAVING count(DISTINCT context_id)>1)',child_table) INTO mismatched;
    IF mismatched THEN
        RAISE EXCEPTION 'conflicting path contexts require explicit reconciliation' USING ERRCODE='23514';
    END IF;
    EXECUTE format('INSERT INTO %s(tenant_id,path_target,context_id)
        SELECT DISTINCT tenant_id,path_target,context_id FROM %s
        ON CONFLICT(tenant_id,path_target) DO NOTHING',parent_table,child_table);
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT entity_path_targets_tenant_fk',parent_table);
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT entity_path_targets_context_fk',parent_table);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=child_oid AND conname='entity_path_test_target_context_fk') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_path_test_target_context_fk
            FOREIGN KEY(tenant_id,path_target,context_id) REFERENCES %s(tenant_id,path_target,context_id)
            DEFERRABLE INITIALLY DEFERRED NOT VALID',child_table,parent_table);
    END IF;
    -- A familiar constraint name alone is not evidence of the correct key,
    -- schema or delete behavior. Refuse any inconsistent installed shape.
    FOR expected IN SELECT * FROM (VALUES
        (parent_oid,'entity_path_targets_tenant_fk','public.tenants'::regclass,
            ARRAY['tenant_id'],ARRAY['id'],false,false,'c'),
        (parent_oid,'entity_path_targets_context_fk',to_regclass(context_table),
            ARRAY['tenant_id','context_id'],ARRAY['tenant_id','id'],false,false,'c'),
        (child_oid,'entity_path_test_target_context_fk',parent_oid,
            ARRAY['tenant_id','path_target','context_id'],ARRAY['tenant_id','path_target','context_id'],true,true,'a'))
        AS keys(relation_oid,key_name,parent_relation,columns,referenced_columns,want_deferrable,want_deferred,delete_action)
    LOOP
        SELECT ARRAY(SELECT attribute.attnum FROM unnest(expected.columns) WITH ORDINALITY names(name,position)
            JOIN pg_attribute attribute ON attribute.attrelid=expected.relation_oid AND attribute.attname=names.name
            ORDER BY names.position) INTO child_columns;
        SELECT ARRAY(SELECT attribute.attnum FROM unnest(expected.referenced_columns) WITH ORDINALITY names(name,position)
            JOIN pg_attribute attribute ON attribute.attrelid=expected.parent_relation AND attribute.attname=names.name
            ORDER BY names.position) INTO parent_columns;
        SELECT * INTO actual FROM pg_constraint WHERE conrelid=expected.relation_oid AND conname=expected.key_name;
        IF NOT FOUND OR actual.contype<>'f' OR actual.confrelid<>expected.parent_relation
           OR actual.conkey<>child_columns OR actual.confkey<>parent_columns
           OR actual.condeferrable<>expected.want_deferrable OR actual.condeferred<>expected.want_deferred
           OR actual.confdeltype::text<>expected.delete_action OR actual.confupdtype<>'a' THEN
            RAISE EXCEPTION 'path target context foreign key differs from the required storage guard' USING ERRCODE='23514';
        END IF;
    END LOOP;
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT entity_path_test_target_context_fk',child_table);
    -- The former unique index also served cleanup and deferred FK checks.
    -- Preserve that access path without preserving its one-test restriction.
    -- Migration0199 builds the pooled index online; existing private schemas
    -- prepare it online before provisioning/catch-up. Fresh LIKE tables copy
    -- it under a new name. Never build an index under this DDL transaction.
    IF NOT EXISTS(SELECT 1 FROM pg_index idx JOIN pg_class relation ON relation.oid=idx.indexrelid
        JOIN pg_am method ON method.oid=relation.relam
        WHERE idx.indrelid=child_oid AND idx.indisvalid AND idx.indisready AND NOT idx.indisunique
          AND idx.indpred IS NULL AND idx.indexprs IS NULL AND idx.indnkeyatts>=2 AND method.amname='btree'
          AND pg_get_indexdef(idx.indexrelid,1,true)='tenant_id'
          AND pg_get_indexdef(idx.indexrelid,2,true)='path_target') THEN
        RAISE EXCEPTION 'path target reference index must be prepared online' USING ERRCODE='23514';
    END IF;
    -- Validate replacement integrity before removing single-test admission.
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS entity_path_target_one_context',child_table);
    EXECUTE format('DROP TRIGGER IF EXISTS entity_path_target_context_guard ON %s',child_table);
    EXECUTE format('CREATE TRIGGER entity_path_target_context_guard BEFORE INSERT OR UPDATE OF
        tenant_id,test_id,context_id,path_target ON %s FOR EACH ROW
        EXECUTE FUNCTION public.probectl_path_target_context_guard()',child_table);
    EXECUTE format('DROP TRIGGER IF EXISTS entity_path_target_context_cleanup ON %s',child_table);
    EXECUTE format('CREATE TRIGGER entity_path_target_context_cleanup AFTER DELETE OR UPDATE OF
        tenant_id,path_target,context_id ON %s FOR EACH ROW
        EXECUTE FUNCTION public.probectl_path_target_context_cleanup()',child_table);
END $$;

-- Existing private schemas keep their stronger old unique constraint until
-- managed-silo catch-up builds the replacement index online, then installs the
-- shared target guard in its normal DDL transaction. Fresh silos copy indexes.
SELECT public.probectl_install_path_target_contexts('public');
