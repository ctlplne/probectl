// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsupport

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InstallFlowHistoryFixture installs disposable private-history SQL only in an
// owned test database with applied migrations and a held LockPostgresPublicCatalog
// lock. Pass tenancy.FlowHistoryOwnerBoundaryPlan so tests use the canonical
// policy without making this low-level support package import tenancy. CREATE
// refuses existing tables; cleanup drops only tables this call created.
// This is not a product migration or a completed history/lifecycle service.
func InstallFlowHistoryFixture(ctx context.Context, t testing.TB, admin *pgxpool.Pool, ownerBoundary func(string, string) []string) {
	t.Helper()
	if ownerBoundary == nil {
		t.Fatal("history fixture requires the canonical owner boundary plan")
	}
	statements := []string{
		`CREATE TABLE public.flow_conversation_epochs(tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,generation bigint NOT NULL CHECK(generation>0),invalidating boolean NOT NULL DEFAULT false,operation_id uuid,operation_kind text,operation_binding bytea,operation_plan text,operation_messages_deleted bigint NOT NULL DEFAULT 0 CHECK(operation_messages_deleted>=0),operation_jobs_deleted bigint NOT NULL DEFAULT 0 CHECK(operation_jobs_deleted>=0),operation_source_empty boolean NOT NULL DEFAULT false,
          CHECK(COALESCE(operation_kind='subject_erase',false) OR (operation_messages_deleted=0 AND operation_jobs_deleted=0 AND NOT operation_source_empty)),
		  CHECK(operation_plan IS NULL OR (invalidating AND operation_kind='subject_erase' AND length(operation_plan)>0)),
          CHECK((NOT invalidating AND operation_id IS NULL AND operation_kind IS NULL AND operation_binding IS NULL) OR
            (invalidating AND operation_id IS NOT NULL AND operation_kind IS NOT NULL AND operation_kind IN ('tenant_erase','subject_erase','retention','key_rotation') AND operation_binding IS NOT NULL AND octet_length(operation_binding)=32)))`,
		`CREATE TABLE public.flow_conversation_messages(tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,owner_id uuid NOT NULL,conversation_id uuid NOT NULL,message_id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),epoch bigint NOT NULL CHECK(epoch>0),parent_message_id uuid,parent_revision bigint,kind text NOT NULL,frozen_at text NOT NULL,expires_at timestamptz,private_header text NOT NULL,private_payload text NOT NULL,position bigint NOT NULL CHECK(position>0),
          PRIMARY KEY(tenant_id,owner_id,conversation_id,message_id,revision),
          UNIQUE(tenant_id,owner_id,conversation_id,position),
          CHECK((parent_message_id IS NULL)=(parent_revision IS NULL)),
          FOREIGN KEY(tenant_id,owner_id,conversation_id,parent_message_id,parent_revision) REFERENCES public.flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision) ON DELETE CASCADE)`,
		`CREATE TABLE public.flow_conversation_jobs(tenant_id uuid NOT NULL,owner_id uuid NOT NULL,conversation_id uuid NOT NULL,job_id uuid NOT NULL,input_message_id uuid NOT NULL,input_revision bigint NOT NULL,epoch bigint NOT NULL CHECK(epoch>0),status text NOT NULL CHECK(status IN ('queued','processing','completed','failed','canceled')),lease_generation bigint NOT NULL CHECK(lease_generation>=0),worker_id uuid,lease_until timestamptz,cancel_revision bigint NOT NULL DEFAULT 0 CHECK(cancel_revision>=0),proposal_message_id uuid,proposal_revision bigint CHECK(proposal_revision>0),
          PRIMARY KEY(tenant_id,owner_id,job_id),
          UNIQUE(tenant_id,owner_id,conversation_id,input_message_id,input_revision),
          CHECK((status='processing' AND worker_id IS NOT NULL AND lease_until IS NOT NULL AND lease_generation>0) OR (status<>'processing' AND worker_id IS NULL AND lease_until IS NULL)),
          CHECK((proposal_message_id IS NULL)=(proposal_revision IS NULL)),
          FOREIGN KEY(tenant_id,owner_id,conversation_id,proposal_message_id,proposal_revision) REFERENCES public.flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision) ON DELETE CASCADE,
          FOREIGN KEY(tenant_id,owner_id,conversation_id,input_message_id,input_revision) REFERENCES public.flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision) ON DELETE CASCADE)`,
		`CREATE TABLE public.flow_conversation_activity(tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,owner_id uuid NOT NULL,operation_id uuid NOT NULL,instance_id uuid NOT NULL,epoch bigint NOT NULL CHECK(epoch>0),started_at timestamptz NOT NULL DEFAULT clock_timestamp(),drained_at timestamptz,
          PRIMARY KEY(tenant_id,owner_id,operation_id),UNIQUE(tenant_id,operation_id))`,
	}
	created := []string{}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for i := len(created) - 1; i >= 0; i-- {
			if _, err := admin.Exec(cleanup, `DROP TABLE public.`+created[i]); err != nil {
				t.Error("owned journal fixture cleanup failed")
			}
		}
	})
	for i, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("journal fixture table already exists or cannot be created", err)
		}
		created = append(created, []string{"flow_conversation_epochs", "flow_conversation_messages", "flow_conversation_jobs", "flow_conversation_activity"}[i])
	}
	for _, table := range created {
		for _, statement := range []string{
			`ALTER TABLE public.` + table + ` ENABLE ROW LEVEL SECURITY`,
			`ALTER TABLE public.` + table + ` FORCE ROW LEVEL SECURITY`,
			`REVOKE ALL ON public.` + table + ` FROM PUBLIC,probectl_provider`,
			`GRANT SELECT,INSERT,UPDATE,DELETE ON public.` + table + ` TO probectl_app`,
			`CREATE POLICY tenant_isolation ON public.` + table + ` USING(tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)`,
		} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		if table == "flow_conversation_messages" || table == "flow_conversation_jobs" {
			if _, err := admin.Exec(ctx, `CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()`); err != nil {
				t.Fatal(err)
			}
		}
		if table == "flow_conversation_activity" {
			if _, err := admin.Exec(ctx, `CREATE TRIGGER tenant_audit_write_fence BEFORE INSERT ON public.flow_conversation_activity FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_audit_write_fence()`); err != nil {
				t.Fatal(err)
			}
		}
		for _, statement := range ownerBoundary("public", table) {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}
}
