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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingTransferArchiveAndReviewStayTenantScoped(t *testing.T) {
	f, history, ports := newRoutingTransferTestFixture(t)
	socket, inputs, _ := seedRoutingTransferTestEstimates(t, f, history, ports)
	t.Run("archive-dry-run", func(t *testing.T) {
		proveRoutingTransferDryRunArchiveScope(t, f, socket, inputs)
	})
	t.Run("review-publication", func(t *testing.T) {
		proveRoutingTransferReviewPublicationScope(t, f, socket, inputs)
	})
}

// Exercise the served authorization and actual source locks. The probe
// delegates publication to the real control path and counts the scoped write
// callback. The EE PostgreSQL test covers persisted decisions and audit rows.
func proveRoutingTransferReviewPublicationScope(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, inputs []routingTransferRequest) {
	t.Helper()
	ops := device.NewPostgresOpsStore(f.pool)
	probe := &routingTransferPublicationProbe{
		pool: f.pool, published: map[string]int{}, beforePublication: map[string]func(context.Context) error{},
	}
	f.server.WithDeviceOps(ops).WithRemediation(probe)
	var selections [2]routingTransferDryRunInput
	var cookies, fingerprints [2]string
	for lane, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permRemediationPropose, "metrics.write"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{
			TenantID: tenant, UserID: f.users[tenant], Email: "transfer-review@example.invalid", DisplayName: "Transfer reviewer",
			MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants),
		})
		if err != nil {
			t.Fatal(err)
		}
		cookies[lane] = cookie
		archive := recordRoutingTransferDryRunArchive(t, f, socket, tenant, lane+20)
		selections[lane] = routingTransferDryRunInput{ArchiveID: archive.ID, Estimate: inputs[lane]}

		body := routingTransferReviewSessionPOST(t, socket, &cookies[lane],
			"/v1/remediation/routing-transfer-dry-run", selections[lane], http.StatusOK)
		var preview remediation.RoutingTransferDryRun
		if err := json.Unmarshal(body, &preview); err != nil || len(preview.PreviewFingerprint) != 64 {
			t.Fatalf("lane %d did not display an exact preview fingerprint: %v", lane, err)
		}
		fingerprints[lane] = preview.PreviewFingerprint
	}

	const route = "/v1/remediation/routing-transfer-reviews"
	propose := func(lane int, selected routingTransferDryRunInput, code int) {
		t.Helper()
		input := routingTransferProposalRequest{Selection: selected, PreviewFingerprint: fingerprints[lane], MaxMovedBPS: "24000"}
		routingTransferReviewSessionPOST(t, socket, &cookies[lane], route, input, code)
	}
	for lane, tenant := range f.tenants {
		refreshRoutingTransferFlowExporter(t, f, tenant, "192.0.2.1")
		sibling := selections[lane]
		sibling.ArchiveID = selections[1-lane].ArchiveID
		propose(lane, sibling, http.StatusNotFound)
		propose(lane, selections[lane], http.StatusCreated)
		if got := probe.publishedCount(tenant); got != 1 {
			t.Fatalf("tenant %d entered the publication callback %d times", lane, got)
		}
	}

	staleTenant := f.tenants[0]
	probe.before(staleTenant, func(ctx context.Context) error {
		cfg := device.ConfigVersion{
			TenantID: staleTenant, Device: "Shared router identity", Source: "operator-submitted",
			Content: "frr version 10.7.1\n! newer review fixture\n", ObservedAt: time.Now().UTC(),
			Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"},
		}
		_, err := ops.ArchiveConfigWithCommit(tenancy.WithTenant(ctx, tenancy.ID(staleTenant)), cfg, nil)
		return err
	})
	propose(0, selections[0], http.StatusConflict)
	propose(1, selections[1], http.StatusCreated)
	if probe.publishedCount(staleTenant) != 1 || probe.publishedCount(f.tenants[1]) != 2 {
		t.Fatal("a replacement archive crossed the review publication boundary")
	}
}

type routingTransferPublicationProbe struct {
	remediation.Service
	pool              *pgxpool.Pool
	mu                sync.Mutex
	published         map[string]int
	beforePublication map[string]func(context.Context) error
}

func (p *routingTransferPublicationProbe) before(tenant string, fn func(context.Context) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beforePublication[tenant] = fn
}

func (p *routingTransferPublicationProbe) publishedCount(tenant string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.published[tenant]
}

func (p *routingTransferPublicationProbe) PreviewRoutingTransfer(ctx context.Context, tenant string,
	evidence remediation.RoutingTransferDryRunEvidence) (remediation.RoutingTransferDryRun, error) {
	principal := auth.PrincipalFrom(ctx)
	current, ok := tenancy.FromContext(ctx)
	if !ok || principal == nil || principal.TenantID != tenant || current.String() != tenant || evidence.TenantID != tenant {
		return remediation.RoutingTransferDryRun{}, entity.ErrScopeMismatch
	}
	return remediation.RoutingTransferDryRun{
		RouterID: evidence.RouterID, ArchiveID: evidence.ArchiveID, ExactPrefix: evidence.ExactPrefix.String(),
		CandidateASN:     evidence.CandidateASN,
		SourceValidUntil: evidence.SourceValidUntil, PreviewFingerprint: evidence.EstimateDigest,
	}, nil
}

func (p *routingTransferPublicationProbe) ProposeRoutingTransfer(ctx context.Context, tenant, _ string,
	selection json.RawMessage, fingerprint, _ string, prepare remediation.RoutingTransferReviewPrepare) (remediation.Proposal, error) {
	preview, evidence, err := prepare(ctx, selection)
	if err != nil {
		return remediation.Proposal{}, err
	}
	if evidence.Publish == nil || fingerprint != preview.PreviewFingerprint {
		return remediation.Proposal{}, remediation.Error{Code: "review_changed", Message: "preview changed before publication"}
	}
	p.mu.Lock()
	hook := p.beforePublication[tenant]
	delete(p.beforePublication, tenant)
	p.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return remediation.Proposal{}, err
		}
	}
	scoped := tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant)))
	err = tenancy.InTenant(scoped, p.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		return evidence.Publish(ctx, sc, permRemediationPropose, func(ctx context.Context, sc tenancy.Scope) error {
			var storedTenant, role string
			if err := sc.Q.QueryRow(ctx, `SELECT current_setting('probectl.tenant_id'), current_user`).Scan(&storedTenant, &role); err != nil {
				return err
			}
			if storedTenant != tenant || role != tenancy.AppRole {
				return entity.ErrScopeMismatch
			}
			p.mu.Lock()
			p.published[tenant]++
			p.mu.Unlock()
			return nil
		})
	})
	if err != nil {
		return remediation.Proposal{}, err
	}
	return remediation.Proposal{TenantID: tenant, State: remediation.StateProposed, Kind: remediation.KindRoutingTransferReview, Target: preview.ExactPrefix}, nil
}

func (*routingTransferPublicationProbe) GetRoutingTransfer(context.Context, string, string, remediation.RoutingTransferReviewPrepare) (remediation.RoutingTransferReview, error) {
	return remediation.RoutingTransferReview{}, remediation.ErrNotProposed
}

func (*routingTransferPublicationProbe) ApproveRoutingTransfer(context.Context, string, string, string, string, string,
	remediation.RoutingTransferReviewPrepare) (remediation.Proposal, error) {
	return remediation.Proposal{}, remediation.ErrNotProposed
}

func routingTransferReviewSessionPOST(t *testing.T, socket *httptest.Server, cookie *string, path string, body any, expected int) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", socket.URL)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: *cookie})
	response, err := socket.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != expected {
		t.Fatalf("review %s returned %d, want %d: %s %v", path, response.StatusCode, expected, raw, err)
	}
	for _, next := range response.Cookies() {
		if next.Name == auth.SessionCookie && next.Value != "" {
			*cookie = next.Value
		}
	}
	return raw
}
