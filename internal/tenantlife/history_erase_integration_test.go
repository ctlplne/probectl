// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type historyEraseFlowStore struct {
	flowstore.Store
	deleted bool
}

func (store *historyEraseFlowStore) DeleteTenant(ctx context.Context, tenant string) (int64, error) {
	store.deleted = true
	return store.Store.DeleteTenant(ctx, tenant)
}

func historyEraseFixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, string, string) {
	t.Helper()
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	config := admin.Config().Copy()
	if dsn := os.Getenv("PROBECTL_WORKER_CREDENTIAL_TEST_DATABASE_URL"); dsn != "" {
		var err error
		config, err = pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("history erasure runtime configuration unavailable")
		}
	} else {
		password, err := crypto.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User = "probectl-qa-beta-history-erase-" + hex.EncodeToString(password[:6])
		config.ConnConfig.Password = hex.EncodeToString(password)
		clear(password)
		role := pgx.Identifier{config.ConnConfig.User}.Sanitize()
		if _, err := admin.Exec(t.Context(), `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+config.ConnConfig.Password+`'`); err != nil {
			t.Fatal("owned history erasure role creation failed")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := admin.Exec(ctx, `DROP ROLE `+role); err != nil {
				t.Error("owned history erasure role cleanup failed")
			}
		})
		for _, statement := range []string{`GRANT probectl_app TO ` + role, `GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`} {
			if _, err := admin.Exec(t.Context(), statement); err != nil {
				t.Fatal("owned history erasure role membership unavailable")
			}
		}
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("history erasure runtime pool unavailable")
	}
	t.Cleanup(pool.Close)
	var super, bypass, tls bool
	if err := pool.QueryRow(t.Context(), `SELECT rolsuper,rolbypassrls,COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass, &tls); err != nil || super || bypass {
		t.Fatal("history erasure requires actual NOSUPERUSER NOBYPASSRLS login")
	}
	if tls {
		t.Log("history erasure runtime TLS transport verified")
	}
	testsupport.InstallFlowHistoryFixture(t.Context(), t, admin, tenancy.FlowHistoryOwnerBoundaryPlan)
	red := mkTenant(t, admin, "probectl-qa-beta-history-red-"+historyEraseUUID(t))
	blue := mkTenant(t, admin, "probectl-qa-beta-history-blue-"+historyEraseUUID(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Exact owned fixture cleanup is not a product drain acknowledgement.
		if _, err := admin.Exec(ctx, `DELETE FROM flow_conversation_activity WHERE tenant_id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(ctx, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	})
	return admin, pool, red, blue
}

func historyEraseUUID(t *testing.T) string {
	t.Helper()
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPooledTenantEraseHistoryUnacknowledgedOperation(t *testing.T) {
	admin, pool, red, _ := historyEraseFixture(t)
	owner, operation := historyEraseUUID(t), historyEraseUUID(t)
	if _, err := admin.Exec(t.Context(), `INSERT INTO flow_conversation_activity(tenant_id,owner_id,operation_id,instance_id,epoch)VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1)`, red, owner, operation, historyEraseUUID(t)); err != nil {
		t.Fatal(err)
	}
	flows := &historyEraseFlowStore{Store: flowstore.NewMemory()}
	engine := New(pool, flows, nil, nil, nil, "owned fixture backups", testLog())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	attestation, err := engine.Erase(ctx, red, "owned-history", "privacy-admin")
	if !errors.Is(err, flowconversation.ErrJournalDraining) || attestation.Complete || flows.deleted {
		t.Fatal("unacknowledged history operation admitted other-store erasure or a successful attestation", err, attestation.Complete, flows.deleted)
	}
	assertTenantStatus(ctx, t, admin, red, "active")
	var active int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND drained_at IS NULL`, red).Scan(&active); err != nil || active != 1 {
		t.Fatal("unknown operation disappeared during refused erasure", err)
	}
}

// Intentionally unreadable source proves that physical full-tenant erasure
// never needs a creator credential, key or permission to SELECT private bytes.
func seedHistoryErasureRows(t *testing.T, admin *pgxpool.Pool, red, blue string) string {
	t.Helper()
	owner, other, conversation := historyEraseUUID(t), historyEraseUUID(t), historyEraseUUID(t)
	root, child := historyEraseUUID(t), historyEraseUUID(t)
	for _, row := range []struct {
		tenant, owner, message string
		parent                 *string
		position               int
	}{{red, owner, root, nil, 1}, {red, owner, child, &root, 2}, {red, other, root, nil, 1}, {blue, owner, root, nil, 1}} {
		var parentRevision any
		if row.parent != nil {
			parentRevision = int64(1)
		}
		if _, err := admin.Exec(t.Context(), `INSERT INTO flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision,epoch,parent_message_id,parent_revision,kind,frozen_at,private_header,private_payload,position)VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,1,$5::uuid,$6,'input','2026-10-30T00:00:00Z','owned unreadable header','owned unreadable payload',$7)`, row.tenant, row.owner, conversation, row.message, row.parent, parentRevision, row.position); err != nil {
			t.Fatal(err)
		}
	}
	job := historyEraseUUID(t)
	for _, row := range [][2]string{{red, owner}, {red, other}, {blue, owner}} {
		if _, err := admin.Exec(t.Context(), `INSERT INTO flow_conversation_jobs(tenant_id,owner_id,conversation_id,job_id,input_message_id,input_revision,epoch,status,lease_generation)VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,1,1,'queued',0)`, row[0], row[1], conversation, job, root); err != nil {
			t.Fatal(err)
		}
	}
	return owner
}

func denyHistoryErasureSource(t *testing.T, admin, pool *pgxpool.Pool, tenant, owner string) {
	t.Helper()
	if _, err := admin.Exec(t.Context(), `REVOKE SELECT ON public.flow_conversation_messages FROM probectl_app`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `GRANT SELECT ON public.flow_conversation_messages TO probectl_app`); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(t.Context(), `GRANT SELECT(tenant_id,owner_id,conversation_id,message_id,revision,epoch,parent_message_id,parent_revision,kind,frozen_at,expires_at,position) ON public.flow_conversation_messages TO probectl_app`); err != nil {
		t.Fatal(err)
	}
	err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.flow_history_owner',$1,true)`, owner); err != nil {
			return err
		}
		var source string
		return sc.Q.QueryRow(ctx, `SELECT private_payload FROM flow_conversation_messages LIMIT 1`).Scan(&source)
	})
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("history erasure fixture still permits private source SELECT", err)
	}
	if err := tenancy.InProvider(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, q tenancy.Querier) error {
		var eligible bool
		return q.QueryRow(ctx, `SELECT status IN ('active','suspended','offboarding') FROM public.tenants WHERE id=$1::uuid`, tenant).Scan(&eligible)
	}); err != nil {
		t.Fatal("source SELECT refusal also denied independent lifecycle registry metadata", err)
	}
}

func assertHistoryErasureRows(t *testing.T, admin *pgxpool.Pool, tenant string, messages, jobs, activity int64) {
	t.Helper()
	var actualMessages, actualJobs, actualActivity int64
	if err := admin.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=$1::uuid)`, tenant).Scan(&actualMessages, &actualJobs, &actualActivity); err != nil {
		t.Fatal(err)
	}
	if actualMessages != messages || actualJobs != jobs || actualActivity != activity {
		t.Fatal("actual owned history counts differ from claimed erasure", actualMessages, actualJobs, actualActivity)
	}
}

func TestPooledTenantEraseHistoryEveryOwnerAndBlue(t *testing.T) {
	admin, pool, red, blue := historyEraseFixture(t)
	owner := seedHistoryErasureRows(t, admin, red, blue)
	denyHistoryErasureSource(t, admin, pool, red, owner)
	engine := New(pool, flowstore.NewMemory(), nil, nil, nil, "owned fixture backups", testLog())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	attestation, err := engine.Erase(ctx, red, "owned-history", "privacy-admin")
	if err != nil || !attestation.Complete {
		t.Fatal("counted multi-owner history did not complete full tenant erasure", err)
	}
	assertHistoryErasureRows(t, admin, red, 0, 0, 0)
	assertHistoryErasureRows(t, admin, blue, 1, 1, 0)
	assertTenantStatus(ctx, t, admin, red, "deleted")
	assertTenantStatus(ctx, t, admin, blue, "active")
	counts := map[string]int64{}
	for _, store := range attestation.Stores {
		if strings.HasPrefix(store.Store, "flow_conversation_") && store.VerifiedZero {
			counts[store.Store] = store.Deleted
		}
	}
	if len(counts) != 3 || counts["flow_conversation_messages"] != 3 || counts["flow_conversation_jobs"] != 2 {
		t.Fatal("history deletion counts missing from the actual full-tenant attestation", counts)
	}
	var epochs int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`, red).Scan(&epochs); err != nil || epochs != 0 {
		t.Fatal("full tenant teardown retained a history epoch", err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision,epoch,kind,frozen_at,private_header,private_payload,position)VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,1,'input','2026-10-30T00:00:00Z','late','late',1)`, red, owner, historyEraseUUID(t), historyEraseUUID(t)); err == nil {
		t.Fatal("late source writer repopulated deleted history after epoch teardown")
	}
}

func refuseHistoryPurgeAudit(t *testing.T, admin *pgxpool.Pool, tenant string) func() {
	t.Helper()
	name := "probectl_qa_beta_history_purge_" + strings.ReplaceAll(historyEraseUUID(t), "-", "")
	function := pgx.Identifier{"public", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(t.Context(), `CREATE FUNCTION `+function+`() RETURNS trigger LANGUAGE plpgsql AS $owned$ BEGIN IF NEW.action='flow.conversation.tenant_purge' AND NEW.data->>'tenant_id'='`+tenant+`' THEN RAISE EXCEPTION 'owned history purge audit refusal'; END IF; RETURN NEW; END $owned$`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON public.provider_audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DROP TRIGGER `+trigger+` ON public.provider_audit_events`); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(ctx, `DROP FUNCTION `+function+`() `); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	return restore
}

func TestPooledTenantEraseHistoryAuditFailureAndBoundedResume(t *testing.T) {
	admin, pool, red, blue := historyEraseFixture(t)
	owner := seedHistoryErasureRows(t, admin, red, blue)
	denyHistoryErasureSource(t, admin, pool, red, owner)
	flows := &historyEraseFlowStore{Store: flowstore.NewMemory()}
	engine := New(pool, flows, nil, nil, nil, "owned fixture backups", testLog())
	restore := refuseHistoryPurgeAudit(t, admin, red)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	attestation, err := engine.Erase(ctx, red, "owned-history", "privacy-admin")
	if err == nil || attestation.Complete || flows.deleted {
		t.Fatal("failed mandatory history purge audit admitted other-store erasure", err)
	}
	assertHistoryErasureRows(t, admin, red, 3, 2, 0)
	assertTenantStatus(ctx, t, admin, red, "offboarding")
	restore()
	operational := tenancy.WithTenant(ctx, tenancy.ID(red))
	allow := func(ctx context.Context, tenant string) error {
		bound, ok := tenancy.FromContext(ctx)
		if !ok || bound.String() != red || tenant != red {
			return errors.New("owned operational tenant mismatch")
		}
		return ctx.Err()
	}
	// Resume the exact durable full-tenant intent through a new Journal. One
	// selected row per transaction must not cascade through the ancestry.
	result, err := flowconversation.NewJournal(pool).EraseTenant(operational, flowconversation.CancellationBudget{Rows: 1, TimeLimit: 3 * time.Second}, allow, func(ctx context.Context) error {
		return engine.fenceTenantAuditWrites(ctx, red, "privacy-admin")
	})
	if err != nil || !result.Installed || result.MessagesDeleted != 3 || result.JobsDeleted != 2 {
		t.Fatal("exact one-row physical purge failed to resume without source/key/creator", err)
	}
	var batches, messages, jobs, plans int64
	if err := admin.QueryRow(ctx, `SELECT count(*),COALESCE(sum((data->>'messages_deleted')::bigint),0)::bigint,COALESCE(sum((data->>'jobs_deleted')::bigint),0)::bigint,count(DISTINCT target) FROM provider_audit_events WHERE action='flow.conversation.tenant_purge' AND data->>'tenant_id'=$1`, red).Scan(&batches, &messages, &jobs, &plans); err != nil || batches != 5 || messages != 3 || jobs != 2 || plans != 1 {
		t.Fatal("bounded purge receipts miscounted rows or silently adopted a successor plan", err, batches, messages, jobs, plans)
	}
	assertHistoryErasureRows(t, admin, red, 0, 0, 0)
	assertHistoryErasureRows(t, admin, blue, 1, 1, 0)
	attestation, err = engine.Erase(ctx, red, "owned-history", "privacy-admin")
	if err != nil || !attestation.Complete || !flows.deleted {
		t.Fatal("fully drained counted history did not allow canonical erasure to finish", err)
	}
	assertTenantStatus(ctx, t, admin, red, "deleted")
}

func TestPooledTenantEraseHistoryPartialSchemaAndOtherIntentRefuse(t *testing.T) {
	admin, pool, red, blue := historyEraseFixture(t)
	seedHistoryErasureRows(t, admin, red, blue)
	flows := &historyEraseFlowStore{Store: flowstore.NewMemory()}
	engine := New(pool, flows, nil, nil, nil, "owned fixture backups", testLog())
	if _, err := admin.Exec(t.Context(), `ALTER TABLE public.flow_conversation_jobs RENAME TO probectl_qa_beta_hidden_history_jobs`); err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() {
		if _, err := admin.Exec(context.Background(), `ALTER TABLE public.probectl_qa_beta_hidden_history_jobs RENAME TO flow_conversation_jobs`); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	attestation, err := engine.Erase(t.Context(), red, "owned-history", "privacy-admin")
	if err == nil || attestation.Complete || flows.deleted {
		t.Fatal("partial history schema admitted other-store erasure", err)
	}
	assertTenantStatus(t.Context(), t, admin, red, "active")
	restore()
	operational := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	request := flowconversation.MaintenanceRequest{ID: historyEraseUUID(t), Kind: flowconversation.MaintenanceSubjectErase}
	copy(request.Binding[:], crypto.Hash([]byte("owned different immutable lifecycle plan")))
	if _, err := flowconversation.NewJournal(pool).BeginInvalidation(operational, request, func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	attestation, err = engine.Erase(t.Context(), red, "owned-history", "privacy-admin")
	if err == nil || attestation.Complete || flows.deleted {
		t.Fatal("full erasure adopted a different pending purpose/plan", err)
	}
	assertTenantStatus(t.Context(), t, admin, red, "active")
	assertHistoryErasureRows(t, admin, red, 3, 2, 0)
	assertHistoryErasureRows(t, admin, blue, 1, 1, 0)
}

func TestPooledTenantEraseHistorySearchPathCannotHideFamily(t *testing.T) {
	admin, pool, red, blue := historyEraseFixture(t)
	seedHistoryErasureRows(t, admin, red, blue)
	schema := "probectl_qa_beta_" + strings.ReplaceAll(historyEraseUUID(t), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), `CREATE SCHEMA `+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `DROP SCHEMA `+quoted); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(t.Context(), `GRANT USAGE ON SCHEMA `+quoted+` TO probectl_app,probectl_provider`); err != nil {
		t.Fatal(err)
	}
	config := pool.Config().Copy()
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	shadowPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(shadowPool.Close)
	flows := &historyEraseFlowStore{Store: flowstore.NewMemory()}
	engine := New(shadowPool, flows, nil, nil, nil, "owned fixture backups", testLog())
	attestation, err := engine.Erase(t.Context(), red, "owned-history", "privacy-admin")
	if !errors.Is(err, flowconversation.ErrJournalUnavailable) || attestation.Complete || flows.deleted {
		t.Fatal("earlier empty search-path schema hid the live history family", err)
	}
	assertTenantStatus(t.Context(), t, admin, red, "active")
	assertHistoryErasureRows(t, admin, red, 3, 2, 0)
	assertHistoryErasureRows(t, admin, blue, 1, 1, 0)
}
