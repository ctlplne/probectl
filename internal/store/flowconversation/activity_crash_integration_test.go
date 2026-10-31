// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This is a subprocess entry point, not a standalone capability proof. Only
// the parent below counts it, after observing its actual durable registration.
func TestActivityOwnedChildProcess(t *testing.T) {
	if os.Getenv("PROBECTL_QA_ACTIVITY_CHILD") != "1" {
		return
	}
	f := newMessageCodecFixture(t)
	f.scope.TenantID = os.Getenv("PROBECTL_QA_ACTIVITY_TENANT")
	f.scope.OwnerID = os.Getenv("PROBECTL_QA_ACTIVITY_OWNER")
	if !historyID(f.scope.TenantID) || !historyID(f.scope.OwnerID) {
		t.Fatal("invalid owned child scope")
	}
	f.context = tenancy.WithTenant(t.Context(), tenancy.ID(f.scope.TenantID))
	var err error
	f.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, f.storedHash)
	if err != nil {
		t.Fatal("owned child identity unavailable")
	}
	config, err := pgxpool.ParseConfig(os.Getenv("PROBECTL_WORKER_CREDENTIAL_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("owned child runtime configuration unavailable")
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("owned child runtime unavailable")
	}
	defer pool.Close()
	err = NewJournal(pool).WithReadLease(f.requestContext(t), f.authorizeHistory, func(ctx context.Context) error {
		private := []byte("owned child private source buffer")
		defer clear(private)
		if _, err := os.Stdout.WriteString("probectl-qa-beta-owned-activity-ready\n"); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal("owned child operation stopped before the parent fault")
	}
}

func TestHistoryJournalPostgresActivityProcessCrashStaysPending(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	// This real child uses the same restricted TLS login and existing fixture
	// schema. It does not acquire the parent's catalog lease or run migrations.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	child := exec.CommandContext(parent, executable, "-test.run=^TestActivityOwnedChildProcess$", "-test.timeout=20s")
	child.Args[0] = "probectl-qa-beta-owned-activity-child"
	child.Env = append(os.Environ(), "PROBECTL_QA_ACTIVITY_CHILD=1", "PROBECTL_QA_ACTIVITY_TENANT="+f.red.scope.TenantID, "PROBECTL_QA_ACTIVITY_OWNER="+f.red.scope.OwnerID)
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = io.Discard
	if err := child.Start(); err != nil {
		t.Fatal("owned source child did not start", err)
	}
	ready, ended := make(chan struct{}), make(chan struct{})
	var exitError error
	go func() { defer close(ended); exitError = child.Wait() }()
	signalReady := sync.OnceFunc(func() { close(ready) })
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if scanner.Text() == "probectl-qa-beta-owned-activity-ready" {
				signalReady()
			}
		}
	}()
	t.Cleanup(func() {
		stop()
		_ = child.Process.Kill()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned child process did not exit")
		}
	})
	select {
	case <-ready:
	case <-ended:
		t.Fatal("owned child exited before its durable source callback")
	case <-parent.Done():
		t.Fatal("owned child registration timed out")
	}
	if f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("child opened source without durable operation record")
	}
	operational := f.operational(t, f.red.scope.TenantID)
	pending, err := f.journal.BeginInvalidation(operational, maintenanceRequestFixture(f.red), allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
		t.Fatal("owned source child stopped before crash injection")
	default:
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal("owned source child crash injection failed", err)
	}
	select {
	case <-ended:
		if exitError == nil || child.ProcessState == nil || child.ProcessState.Success() {
			t.Fatal("owned child did not report a crash")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned source child was not reaped")
	}
	if f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("process crash silently acknowledged source drain")
	}
	retry, err := f.journal.RetryDrainedOperations(operational, ActivityBudget{Rows: 8, TimeLimit: time.Second}, allowActivityMaintenance)
	if err != nil || retry.Acknowledged != 0 || f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("new process adopted a crashed instance's private acknowledgement", err)
	}
	batch, err := f.journal.CancelInvalidated(operational, pending, CancellationBudget{Rows: 1, TimeLimit: time.Second}, allowActivityMaintenance)
	if err != nil || batch.ActiveRemaining != 0 {
		t.Fatal("owned no-job cancellation fixture failed", err)
	}
	if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_activity SET started_at=clock_timestamp()-interval '30 days' WHERE tenant_id=$1::uuid`, f.red.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { t.Error("unknown orphan entered destructive callback"); return nil }); !errors.Is(err, ErrJournalDraining) {
		t.Fatal("process/session loss,age or zero jobs became a drain acknowledgement", err)
	}
	t.Log("owned child process killed and reaped; unknown orphan remains pending,not recovered")
	// Exact owned fixture cleanup only after Wait positively proved this child
	// exited. This is not an implemented product orphan-fencing/recovery API.
	if changed, err := f.admin.Exec(t.Context(), `DELETE FROM flow_conversation_activity WHERE tenant_id=$1::uuid`, f.red.scope.TenantID); err != nil || changed.RowsAffected() != 1 {
		t.Fatal("owned crashed-instance fixture cleanup failed", err)
	}
}
