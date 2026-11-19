// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func TestProspectConversionAndDeliveredExpirySerializeAtWriteFence(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	flows := flowstore.NewMemory()
	metrics := &prospectErasureMetrics{Memory: tsdb.NewMemory()}
	engine := tenantlife.New(f.pool, flows, nil, metrics, nil, "owned test fixture", f.server.log)
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)).WithFlowStore(flows).WithTenantLife(engine)
	_, relay, transport := startProspectTestArchive(t, f)
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: transport})
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	pair := newExpiringProspectPair(t, f)
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-time.After(time.Until(pair.end) + time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, tenant := range f.tenants {
		if err := metrics.Write(ctx, []tsdb.Series{{Metric: "assessment_sample", Labels: map[string]string{tsdb.TenantLabel: tenant},
			Value: 1, TimeMillis: pair.end.Add(-time.Second).UnixMilli()}}); err != nil {
			t.Fatal(err)
		}
		if err := supervisor.materializeProspectAssessment(ctx, tenant, "Prospect", now); err != nil {
			t.Fatal(err)
		}
	}
	// Start the delivery tick after both artifact transactions committed. The
	// queue uses PostgreSQL's transaction clock rather than the render tick.
	var deliverAt time.Time
	if err := f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&deliverAt); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		if err := supervisor.deliverTenantReportEmails(ctx, tenant, deliverAt); err != nil {
			t.Fatal(err)
		}
	}
	if len(relay.Messages()) != len(f.tenants) {
		t.Fatal("both race lanes require accepted archived delivery before entering the fence")
	}
	kept, erased := f.tenants[0], f.tenants[1]
	fence := func(tenant string, admit func(context.Context, tenancy.Scope) error) (func() error, string) {
		t.Helper()
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		engagement, evidence, err := supervisor.dueProspectErasureEvidence(bound)
		if err != nil || evidence == nil {
			t.Fatal("the expiry candidate needs an exact consent and delivery receipt", err)
		}
		metadata, capture, err := f.server.verifyProspectErasureReport(bound, engagement, *evidence)
		if err != nil {
			t.Fatal(err)
		}
		return func() error {
			att, err := engine.EraseProspect(bound, tenant, engagement, *evidence, dashboardReportSchedulerActor,
				func(ctx context.Context, sc tenancy.Scope) error {
					if err := f.server.revalidateProspectErasure(ctx, sc, engagement, metadata, capture); err != nil {
						return err
					}
					return admit(ctx, sc)
				})
			if err != nil {
				return err
			}
			return requireCompleteProspectErasure(att)
		}, evidence.BodySHA256
	}
	convert := func(tenant string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, pair.socket.URL+"/v1/lifecycle/prospect/convert", strings.NewReader(`{"revision":1}`))
		if err != nil {
			return 0, err
		}
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: pair.sessions[tenant]})
		req.Header.Set("Origin", pair.socket.URL)
		req.Header.Set("Content-Type", "application/json")
		res, err := pair.socket.Client().Do(req)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()
		if res.StatusCode == http.StatusOK {
			var out store.ProspectEngagement
			if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out); err != nil || out.Revision != 2 || out.ConvertedAt == nil || out.ConsentRevokedAt == nil {
				return res.StatusCode, errors.New("conversion lost its exact revision or withdrawal")
			}
		}
		return res.StatusCode, nil
	}
	type conversionResult struct {
		code int
		err  error
	}
	startConvert := func(tenant string) <-chan conversionResult {
		done := make(chan conversionResult, 1)
		go func() {
			code, err := convert(tenant)
			done <- conversionResult{code, err}
		}()
		return done
	}
	startFence := func(apply func() error) <-chan error {
		done := make(chan error, 1)
		go func() { done <- apply() }()
		return done
	}

	// Conversion owns the shared writer lease while queued behind the audit
	// lock. A prepared expiry with the old receipt queues behind conversion.
	apply, _ := fence(kept, func(context.Context, tenancy.Scope) error {
		return errors.New("a changed consent reached source revalidation")
	})
	gate, release := make(chan int32, 1), make(chan struct{})
	holdAudit := startFence(func() error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(kept)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := audit.LockTenantStream(ctx, sc.Q, kept); err != nil {
				return err
			}
			return holdProspectFenceRace(ctx, sc, gate, release)
		})
	})
	gatePID := awaitProspectFenceRace(ctx, t, gate, holdAudit)
	conversion := startConvert(kept)
	conversionPID := waitProspectFenceBlocker(ctx, t, f.pool, gatePID)
	expiry := startFence(apply)
	waitProspectFenceBlocker(ctx, t, f.pool, conversionPID)
	close(release)
	if err := <-holdAudit; err != nil {
		t.Fatal(err)
	}
	if outcome := <-conversion; outcome.err != nil || outcome.code != http.StatusOK {
		t.Fatal("the queued conversion did not commit first", outcome)
	}
	if err := <-expiry; err == nil || !strings.Contains(err.Error(), "changed before the erasure fence") || metrics.attempts != 0 {
		t.Fatal("stale expiry reached a store after conversion", err)
	}
	verifyProspectRegistryState(t, f, kept, "active", false)
	if err := tenancy.NewPostgresCollectionWriterFence(f.pool).WithTenantWrites(ctx, []string{kept}, func(context.Context) error { return nil }); err != nil {
		t.Fatal("winning conversion left the tenant collection cutoff armed", err)
	}

	// Expiry holds the exclusive writer lease inside the canonical fence.
	// The competing actual HTTPS handler cannot commit its conversion.
	gate, release = make(chan int32, 1), make(chan struct{})
	apply, digest := fence(erased, func(ctx context.Context, sc tenancy.Scope) error {
		return holdProspectFenceRace(ctx, sc, gate, release)
	})
	expiry = startFence(apply)
	gatePID = awaitProspectFenceRace(ctx, t, gate, expiry)
	conversion = startConvert(erased)
	waitProspectFenceBlocker(ctx, t, f.pool, gatePID)
	close(release)
	if err := <-expiry; err != nil {
		t.Fatal("the admitted expiry failed to erase", err)
	}
	if outcome := <-conversion; outcome.err != nil || outcome.code < 400 || metrics.attempts != 1 {
		t.Fatal("the late conversion proceeded past a committed expiry fence", outcome)
	}
	verifyProspectRegistryState(t, f, erased, "deleted", true)
	verifyArchivedProspectAttestation(t, f, erased, pair.inputs[erased].ConfirmTenant, digest, 0)
}

func holdProspectFenceRace(ctx context.Context, sc tenancy.Scope, entered chan<- int32, release <-chan struct{}) error {
	var pid int32
	if err := sc.Q.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return err
	}
	entered <- pid
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func awaitProspectFenceRace(ctx context.Context, t *testing.T, entered <-chan int32, finished <-chan error) int32 {
	t.Helper()
	select {
	case pid := <-entered:
		return pid
	case err := <-finished:
		t.Fatal("the transaction finished before reaching the lock barrier", err)
	case <-ctx.Done():
		t.Fatal("the transaction did not reach its lock barrier", ctx.Err())
	}
	return 0
}

func waitProspectFenceBlocker(ctx context.Context, t *testing.T, pool *pgxpool.Pool, holder int32) int32 {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiter int32
		err := pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) ORDER BY pid LIMIT 1`, holder).Scan(&waiter)
		if err == nil {
			return waiter
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("no conflicting transaction reached the canonical lock", ctx.Err())
		case <-tick.C:
		}
	}
}
