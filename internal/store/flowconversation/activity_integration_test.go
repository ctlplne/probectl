// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type activityFixture struct {
	admin, pool *pgxpool.Pool
	journal     *Journal
	red, blue   messageCodecFixture
}

func newActivityFixture(t *testing.T) activityFixture {
	t.Helper()
	admin, pool := journalFixture(t)
	if admin == nil {
		return activityFixture{}
	}
	red := newMessageCodecFixture(t)
	blue := red
	blue.scope.TenantID = mustInvalidationUUID(t)
	blue.context = tenancy.WithTenant(t.Context(), tenancy.ID(blue.scope.TenantID))
	var err error
	blue.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, blue.scope.TenantID, blue.scope.OwnerID, blue.credentialID, blue.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	tenants := []string{red.scope.TenantID, blue.scope.TenantID}
	for _, tenant := range tenants {
		if _, err := admin.Exec(t.Context(), `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned actual-operation fixture')`, tenant, "probectl-qa-beta-activity-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	journal := NewJournal(pool)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, tenant := range tenants {
			scoped := tenancy.WithTenant(cleanup, tenancy.ID(tenant))
			if retry, err := journal.RetryDrainedOperations(scoped, ActivityBudget{Rows: 8, TimeLimit: 2 * time.Second}, allowActivityMaintenance); err != nil || retry.Pending != 0 {
				t.Error("owned already-drained acknowledgement cleanup failed", err)
			}
		}
		var active int
		if err := admin.QueryRow(cleanup, `SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=ANY($1::uuid[]) AND drained_at IS NULL`, tenants).Scan(&active); err != nil || active != 0 {
			t.Error("owned fixture still has unacknowledged source operations", err, active)
		}
		// Exact owned fixture reclamation after the assertion; never an erasure receipt.
		if _, err := admin.Exec(cleanup, `DELETE FROM flow_conversation_activity WHERE tenant_id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	return activityFixture{admin, pool, journal, red, blue}
}
func allowActivityMaintenance(ctx context.Context, tenant string) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant {
		return ErrMessageDenied
	}
	return ctx.Err()
}
func (f activityFixture) active(t *testing.T, tenant string) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND drained_at IS NULL`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f activityFixture) operational(t *testing.T, tenant string) context.Context {
	t.Helper()
	return tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
}
func activityAuditFault(t *testing.T, admin *pgxpool.Pool, table, tenant string, action ...string) func() {
	t.Helper()
	event := "flow.conversation.operation_drained"
	if len(action) > 0 {
		if len(action) != 1 || action[0] != "flow.conversation.operation_started" && action[0] != "flow.conversation.export_started" {
			t.Fatal("invalid owned audit fault action")
		}
		event = action[0]
	}
	name := "probectl_qa_beta_activity_" + strings.ReplaceAll(mustInvalidationUUID(t), "-", "")
	fn := pgx.Identifier{"public", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	target := pgx.Identifier{"public", table}.Sanitize()
	if _, err := admin.Exec(t.Context(), `CREATE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $owned$ BEGIN IF NEW.action='`+event+`' AND COALESCE(NEW.data->>'tenant_id',to_jsonb(NEW)->>'tenant_id')='`+tenant+`' THEN RAISE EXCEPTION 'owned acknowledgement audit refusal'; END IF; RETURN NEW; END $owned$`); err != nil {
		t.Fatal(err)
	}
	createdTrigger := false
	restore := sync.OnceFunc(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if createdTrigger {
			if _, err := admin.Exec(cleanup, `DROP TRIGGER `+trigger+` ON `+target); err != nil {
				t.Error(err)
			}
		}
		if _, err := admin.Exec(cleanup, `DROP FUNCTION `+fn+`() `); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	if _, err := admin.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON `+target+` FOR EACH ROW EXECUTE FUNCTION `+fn+`() `); err != nil {
		t.Fatal(err)
	}
	createdTrigger = true
	return restore
}

func TestHistoryJournalPostgresActivityDrainSurvivesLeaseLoss(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	ctx := f.red.requestContext(t)
	run, cancel := context.WithCancel(ctx)
	started, canceled, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	releaseSource := sync.OnceFunc(func() { close(release) })
	go func() {
		defer close(ended)
		finished <- f.journal.WithReadLease(run, f.red.authorizeHistory, func(current context.Context) error {
			private := []byte("owned private callback buffer")
			defer clear(private)
			close(started)
			<-current.Done()
			close(canceled)
			<-release
			return current.Err()
		})
	}()
	t.Cleanup(func() {
		cancel()
		releaseSource()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned source callback did not drain")
		}
	})
	select {
	case <-started:
	case err := <-finished:
		t.Fatal("source registration did not enter actual callback", err)
	case <-time.After(5 * time.Second):
		t.Fatal("source callback start timed out")
	}
	if f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("source callback opened before durable registration")
	}
	if err := tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		changed, err := sc.Q.Exec(ctx, `DELETE FROM flow_conversation_activity WHERE tenant_id=$1::uuid`, f.red.scope.TenantID)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 0 {
			t.Error("lifecycle owner binding erased an active drain proof")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	operational := f.operational(t, f.red.scope.TenantID)
	request := maintenanceRequestFixture(f.red)
	pending, err := f.journal.BeginInvalidation(operational, request, allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("actual source callback never observed cancellation")
	}
	var pid int
	if err := f.admin.QueryRow(t.Context(), `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:'||$1::text,0) AS value)
   SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key WHERE l.locktype='advisory' AND l.granted AND l.mode='ShareLock' AND l.objsubid=1 AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.red.scope.TenantID).Scan(&pid); err != nil {
		t.Fatal("owned source lease backend not observed", err)
	}
	var killed bool
	if err := f.admin.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
		t.Fatal("owned lease fault failed", err)
	}
	replicaPool, err := pgxpool.NewWithConfig(t.Context(), f.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replicaPool.Close)
	replica := NewJournal(replicaPool)
	entered := false
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { entered = true; return nil }); !errors.Is(err, ErrJournalDraining) || entered {
		t.Fatal("lost lease/cancellation admitted an undrained destructive callback", err)
	}
	blueCtx := f.blue.requestContext(t)
	if err := replica.WithReadLease(blueCtx, f.blue.authorizeHistory, func(context.Context) error { return nil }); err != nil {
		t.Fatal("red unknown drain blocked independently scoped blue source", err)
	}
	releaseSource()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled source returned success", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released source callback did not drain")
	}
	if f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("actual callback drain did not commit acknowledgement")
	}
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { entered = true; return nil }); err != nil || !entered {
		t.Fatal("confirmed actual drain retained barrier", err)
	}
	if _, err := replica.CandidateEpoch(ctx); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("drain-only callback cleared an unverified lifecycle intent", err)
	}
}

func TestHistoryJournalPostgresActivityRetryAndOffboardingAudit(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	ctx := f.red.requestContext(t)
	operational := f.operational(t, f.red.scope.TenantID)
	refuseStart := activityAuditFault(t, f.admin, "audit_events", f.red.scope.TenantID, "flow.conversation.operation_started")
	if err := f.journal.WithReadLease(ctx, f.red.authorizeHistory, func(context.Context) error {
		t.Error("source callback entered without durable registration audit")
		return nil
	}); !errors.Is(err, ErrJournalUnavailable) || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("failed registration left source activity or success", err)
	}
	refuseStart()
	restore := activityAuditFault(t, f.admin, "audit_events", f.red.scope.TenantID)
	entered := false
	if err := f.journal.WithReadLease(ctx, f.red.authorizeHistory, func(context.Context) error { entered = true; return nil }); !errors.Is(err, ErrJournalUnavailable) || !entered || f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("acknowledgement audit failure lost its durable active row", err)
	}
	if err := f.journal.WithReadLease(ctx, f.red.authorizeHistory, func(context.Context) error {
		t.Error("pending acknowledgement exceeded same-tenant resources")
		return nil
	}); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("unbounded pending references entered source", err)
	}
	if err := f.journal.WithReadLease(f.blue.requestContext(t), f.blue.authorizeHistory, func(context.Context) error { return nil }); err != nil {
		t.Fatal("red acknowledgement backpressure stopped blue", err)
	}
	if retry, err := f.journal.RetryDrainedOperations(operational, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allowActivityMaintenance); retry != (ActivityRetry{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("audit-refused retry fabricated acknowledgement", err)
	}
	restore()
	if retry, err := NewJournal(f.pool).RetryDrainedOperations(operational, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allowActivityMaintenance); err != nil || retry.Acknowledged != 1 || retry.Pending != 0 || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("same-runtime retry lost already-drained reference", err)
	}

	blue := f.blue
	blueCtx := blue.requestContext(t)
	blueOperational := f.operational(t, blue.scope.TenantID)
	started, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	releaseSource := sync.OnceFunc(func() { close(release) })
	go func() {
		defer close(ended)
		finished <- f.journal.WithReadLease(blueCtx, blue.authorizeHistory, func(context.Context) error { close(started); <-release; return nil })
	}()
	t.Cleanup(func() {
		releaseSource()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned offboarding source did not drain")
		}
	})
	select {
	case <-started:
	case err := <-finished:
		t.Fatal("offboarding source did not start", err)
	case <-time.After(5 * time.Second):
		t.Fatal("offboarding source start timed out")
	}
	pending, err := f.journal.BeginInvalidation(blueOperational, maintenanceRequestFixture(blue), allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(t.Context(), `UPDATE tenants SET status='offboarding',audit_write_fenced_at=clock_timestamp() WHERE id=$1::uuid`, blue.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	var tenantHead int64
	if err := f.admin.QueryRow(t.Context(), `SELECT COALESCE(max(seq),0) FROM audit_events WHERE tenant_id=$1::uuid`, blue.scope.TenantID).Scan(&tenantHead); err != nil {
		t.Fatal(err)
	}
	restoreProvider := activityAuditFault(t, f.admin, "provider_audit_events", blue.scope.TenantID)
	releaseSource()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrJournalGeneration) || !errors.Is(err, ErrJournalUnavailable) {
			t.Fatal("offboarding lost source fence or provider acknowledgement audit error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("offboarding source did not finish")
	}
	if f.active(t, blue.scope.TenantID) != 1 {
		t.Fatal("failed provider receipt acknowledged source drain")
	}
	restoreProvider()
	if retry, err := f.journal.RetryDrainedOperations(blueOperational, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allowActivityMaintenance); err != nil || retry.Acknowledged != 1 || retry.Pending != 0 {
		t.Fatal("offboarded creator-free retry could not append provider lifecycle receipt", err)
	}
	var unchanged int64
	var providerReceipts int
	if err := f.admin.QueryRow(t.Context(), `SELECT COALESCE(max(seq),0) FROM audit_events WHERE tenant_id=$1::uuid`, blue.scope.TenantID).Scan(&unchanged); err != nil || unchanged != tenantHead {
		t.Fatal("retirement wrote tenant audit after its fence", err)
	}
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM provider_audit_events WHERE action='flow.conversation.operation_drained' AND data->>'tenant_id'=$1`, blue.scope.TenantID).Scan(&providerReceipts); err != nil || providerReceipts != 1 {
		t.Fatal("separate provider acknowledgement receipt missing or duplicated", err)
	}
	if err := f.journal.WithDrainedInvalidation(blueOperational, pending, allowActivityMaintenance, func(context.Context) error { return nil }); err != nil {
		t.Fatal("confirmed offboarding drain remained unavailable", err)
	}
}

func TestHistoryJournalPostgresActivityGuardSiloPolicyRestore(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	schema := "probectl_qa_beta_activity_" + strings.ReplaceAll(mustInvalidationUUID(t), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	table := pgx.Identifier{schema, "flow_conversation_activity"}.Sanitize()
	if _, err := f.admin.Exec(t.Context(), `CREATE SCHEMA `+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.admin.Exec(cleanup, `DROP SCHEMA `+quoted+` CASCADE`); err != nil {
			t.Error("owned activity policy schema cleanup failed", err)
		}
	})
	for _, statement := range []string{`CREATE TABLE ` + table + ` (LIKE public.flow_conversation_activity INCLUDING ALL)`, `ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY`, `ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY`, `GRANT USAGE ON SCHEMA ` + quoted + ` TO probectl_app,probectl_provider`, `GRANT SELECT,INSERT,UPDATE,DELETE ON ` + table + ` TO probectl_app`, `CREATE POLICY tenant_isolation ON ` + table + ` USING(tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)`} {
		if _, err := f.admin.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	restore := func() {
		t.Helper()
		for _, statement := range tenancy.FlowHistoryOwnerBoundaryPlan(schema, "flow_conversation_activity") {
			if _, err := f.admin.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	restore()
	if err := tenancy.AssertFlowHistoryOwnerGuard(t.Context(), f.admin, schema, "flow_conversation_activity"); err != nil {
		t.Fatal("restored silo activity guard refused", err)
	}
	for _, fault := range []string{`DROP POLICY flow_history_drained_delete ON ` + table, `ALTER POLICY flow_history_drained_delete ON ` + table + ` USING(true)`, `GRANT TRUNCATE ON ` + table + ` TO probectl_app`} {
		if _, err := f.admin.Exec(t.Context(), fault); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.AssertFlowHistoryOwnerGuard(t.Context(), f.admin, schema, "flow_conversation_activity"); err == nil {
			t.Fatal("missing/widened activity deletion or table-wide privilege passed posture")
		}
		if _, err := f.admin.Exec(t.Context(), `REVOKE TRUNCATE ON `+table+` FROM probectl_app`); err != nil {
			t.Fatal(err)
		}
		restore()
	}
	shared := mustInvalidationUUID(t)
	otherOwner := mustInvalidationUUID(t)
	for _, row := range []struct{ tenant, owner, operation string }{{f.red.scope.TenantID, f.red.scope.OwnerID, shared}, {f.red.scope.TenantID, otherOwner, mustInvalidationUUID(t)}, {f.blue.scope.TenantID, f.blue.scope.OwnerID, shared}} {
		if _, err := f.admin.Exec(t.Context(), `INSERT INTO `+table+`(tenant_id,owner_id,operation_id,instance_id,epoch)VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1)`, row.tenant, row.owner, row.operation, f.red.credentialID); err != nil {
			t.Fatal(err)
		}
	}
	if err := tenancy.InTenant(f.red.requestContext(t), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindOwner(ctx, sc, f.red.scope.OwnerID); err != nil {
			return err
		}
		var n int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Error("silo activity owner/tenant RLS allowed a foreign registration")
		}
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		changed, err := sc.Q.Exec(ctx, `DELETE FROM `+table)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 0 {
			t.Error("silo lifecycle binding deleted active source proof")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryJournalPostgresActivitySourceContextAndPrivateOwnership(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	ctx := f.red.requestContext(t)
	if err := f.journal.WithReadLease(ctx, f.red.authorizeHistory, func(current context.Context) error {
		lease, ok := current.Value(operationLeaseKey{}).(*operationLease)
		if !ok || lease.activity == nil {
			t.Fatal("source context has no exact private registration")
		}
		ref := lease.activity
		successor := f.red
		successor.credentialID = mustInvalidationUUID(t)
		var err error
		successor.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, successor.scope.TenantID, successor.scope.OwnerID, successor.credentialID, successor.storedHash)
		if err != nil {
			t.Fatal(err)
		}
		successorCtx := auth.WithPrincipal(current, auth.PrincipalFrom(successor.requestContext(t)))
		if _, err := f.journal.CandidateEpoch(successorCtx); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("successor credential borrowed an existing source operation", err)
		}
		if _, err := NewJournal(f.pool).CandidateEpoch(current); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("different journal borrowed an existing source operation", err)
		}
		copied := *ref
		copied.drained, copied.retiring = true, true
		cleanup, cancel := cleanupActivityContext(current, &copied)
		defer cancel()
		if err := f.journal.retireActivity(cleanup, &copied); !errors.Is(err, ErrMessageDenied) || f.active(t, f.red.scope.TenantID) != 1 {
			t.Fatal("borrowed SQL IDs acknowledged still-active source", err)
		}
		blueCtx := f.blue.requestContext(t)
		borrowed := auth.WithPrincipal(tenancy.WithTenant(current, tenancy.ID(f.blue.scope.TenantID)), auth.PrincipalFrom(blueCtx))
		if _, err := f.journal.CandidateEpoch(borrowed); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("source context crossed tenant through a valid foreign credential", err)
		}
		replacement := mustInvalidationUUID(t)
		if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_activity SET instance_id=$3::uuid WHERE tenant_id=$1::uuid AND operation_id=$2::uuid`, ref.tenant, ref.operation, replacement); err != nil {
			t.Fatal(err)
		}
		_, lost := f.journal.CandidateEpoch(current)
		if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_activity SET instance_id=$3::uuid WHERE tenant_id=$1::uuid AND operation_id=$2::uuid`, ref.tenant, ref.operation, ref.instance); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(lost, ErrJournalLease) {
			t.Fatal("changed durable source registration remained usable", lost)
		}
		return nil
	}); err != nil {
		t.Fatal("restored current source could not drain", err)
	}
	if f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("private source acknowledgement leaked")
	}
}
