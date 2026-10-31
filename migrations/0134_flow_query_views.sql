-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX1: complete private/tenant-shared query configuration. No result data,
-- cursor secret or caller-supplied tenant selector is stored in the definition.
CREATE TABLE IF NOT EXISTS flow_query_views (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 id uuid NOT NULL,
 owner_id text NOT NULL CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
 name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
 visibility text NOT NULL CHECK (visibility IN ('private','tenant')),
 definition jsonb NOT NULL CHECK (jsonb_typeof(definition)='object'
   AND octet_length(definition::text)<=4194304
   AND definition ?& ARRAY['name','visibility','plan','time']
   AND definition->>'name'=name AND definition->>'visibility'=visibility),
 version bigint NOT NULL CHECK (version>=1),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id,id)
);
CREATE INDEX IF NOT EXISTS flow_query_views_tenant_name_idx ON flow_query_views(tenant_id,name COLLATE "C",id);
CREATE INDEX IF NOT EXISTS flow_query_views_tenant_owner_idx ON flow_query_views(tenant_id,owner_id,id);
CREATE TABLE IF NOT EXISTS flow_query_view_preferences (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 owner_id text NOT NULL CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
 view_id uuid NOT NULL,
 favorite boolean NOT NULL DEFAULT false,
 last_opened_at timestamptz,
 PRIMARY KEY (tenant_id,owner_id,view_id),
 FOREIGN KEY (tenant_id,view_id) REFERENCES flow_query_views(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS flow_query_view_preferences_recent_idx ON flow_query_view_preferences(tenant_id,owner_id,last_opened_at DESC,view_id);
ALTER TABLE flow_query_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_query_views FORCE ROW LEVEL SECURITY;
ALTER TABLE flow_query_view_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_query_view_preferences FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON flow_query_views;
CREATE POLICY tenant_isolation ON flow_query_views
 USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON flow_query_view_preferences;
CREATE POLICY tenant_isolation ON flow_query_view_preferences
 USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON flow_query_views,flow_query_view_preferences TO probectl_app;
INSERT INTO permissions(key,description) VALUES('flow.views.write','Create, modify and delete own private or tenant-shared flow queries') ON CONFLICT(key) DO NOTHING;
INSERT INTO role_permissions(tenant_id,role_id,permission_key)
 SELECT r.tenant_id,r.id,'flow.views.write' FROM roles r
 JOIN public.tenants t ON t.id=r.tenant_id
 WHERE r.slug='admin' AND r.is_system
 AND t.status IN ('active','suspended') AND t.audit_write_fenced_at IS NULL
 ON CONFLICT(role_id,permission_key) DO NOTHING;

-- New tenant-owned tables participate in the canonical offboarding fence
-- from their first creation, including table-owner and replication writes.
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_query_views;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON flow_query_views
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_query_views ENABLE ALWAYS TRIGGER tenant_write_fence;
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_query_view_preferences;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON flow_query_view_preferences
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_query_view_preferences ENABLE ALWAYS TRIGGER tenant_write_fence;
