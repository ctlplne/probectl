// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestProspectProviderWithdrawalFencesInFlightAssessment(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)).WithFlowStore(flowstore.NewMemory())
	_, _, relay := startProspectTestArchive(t, f)
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: relay})
	queue := f.server.ProspectProviderQueue()
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok || queue == nil {
		t.Fatal("prospect report services are unavailable")
	}
	supervisor.WithReportSources(f.server)
	pair := newExpiringProspectPair(t, f)
	const route = "/v1/lifecycle/prospect/provider-access"
	for _, tenant := range f.tenants {
		callComplianceControlReport(t, pair.socket, pair.sessions[tenant], http.MethodPost, route,
			map[string]any{"engagement_revision": 1, "access_revision": 0, "allowed": true}, http.StatusOK)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(time.Until(pair.end) + time.Millisecond):
	}
	request := func(tenant string) prospectProviderRequest {
		t.Helper()
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		input := reporting.ProspectProviderRequest{ID: id, EngagementRevision: 1, AccessRevision: 1}
		status, err := queue.RequestAssessment(ctx, tenant, "fixture-operator", input)
		if err != nil || !status.Pending || status.RequestID != id {
			t.Fatal("the consented request was not queued", err)
		}
		return prospectProviderRequest{tenant: tenant, request: input}
	}
	withdrawn, sibling := request(f.tenants[0]), request(f.tenants[1])
	finished := make(chan error, 1)
	// Pause at the final audit lock, after the original data was read and a
	// PDF was rendered. Commit withdrawal before releasing that publication.
	f.in(withdrawn.tenant, func(txCtx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(txCtx, sc.Q, withdrawn.tenant); err != nil {
			return err
		}
		var holder int32
		if err := sc.Q.QueryRow(txCtx, `SELECT pg_backend_pid()`).Scan(&holder); err != nil {
			return err
		}
		go func() { finished <- supervisor.runProviderProspectRequest(ctx, withdrawn) }()
		waiter := waitProspectFenceBlocker(ctx, t, f.pool, holder)
		var waitingOnAudit bool
		if err := f.pool.QueryRow(ctx, `SELECT strpos(query,$2)>0 FROM pg_stat_activity WHERE pid=$1`, waiter,
			"hashtextextended('audit:'").Scan(&waitingOnAudit); err != nil {
			return err
		}
		if !waitingOnAudit {
			return errors.New("the worker must reach its final audit lock")
		}
		// The worker has already acquired its shared writer lease. Taking
		// the same shared lease now allows the scoped withdrawal transaction.
		if err := tenancy.AcquireTenantWriteLease(txCtx, sc); err != nil {
			return err
		}
		owner := f.users[withdrawn.tenant]
		access, err := (store.ProspectEngagements{}).SetProviderAccess(txCtx, sc, owner, 1, 1, false)
		if err != nil || access.Allowed {
			return errors.Join(err, errors.New("could not withdraw the current provider grant"))
		}
		return audit.TenantRecord(txCtx, sc, owner, prospectProviderAccessAudit, withdrawn.tenant, map[string]any{"allowed": false})
	})
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("the withdrawn request should have been discarded", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := supervisor.runProviderProspectRequest(ctx, sibling); err != nil {
		t.Fatal("the sibling's independent request could not file", err)
	}
	f.in(withdrawn.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		engagement, err := (store.ProspectEngagements{}).Get(ctx, sc)
		if err == nil && (engagement.AssessmentArtifactID != "" || !engagement.HasCurrentDeliveryConsent()) {
			t.Fatal("the withdrawn work filed or changed the separate erasure consent")
		}
		return err
	})
	var siblingArtifact string
	f.in(sibling.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		engagement, err := (store.ProspectEngagements{}).Get(ctx, sc)
		siblingArtifact = engagement.AssessmentArtifactID
		return err
	})
	if siblingArtifact == "" {
		t.Fatal("the sibling's report was not filed")
	}
	download := "/v1/dashboard-report-artifacts/" + siblingArtifact
	raw := callComplianceControlReport(t, pair.socket, pair.sessions[sibling.tenant], http.MethodGet, download, nil, http.StatusOK)
	if !bytes.HasPrefix(raw, []byte("%PDF-")) {
		t.Fatal("the sibling did not receive its own PDF")
	}
	callComplianceControlReport(t, pair.socket, pair.sessions[withdrawn.tenant], http.MethodGet, download, nil, http.StatusNotFound)
}
