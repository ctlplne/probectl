//go:build integration

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

func TestResolverDNSKeepsCapturedPressureAndIncidentsInTheAssignedTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	correlator := incident.NewCorrelator(pgIncidentStore{pool: f.pool}, 10*time.Minute, f.server.log)
	newSender := newVerdictEvidenceSender(t, f, correlator)
	const sameName = "regional-resolver"
	start := time.Now().UTC().Truncate(time.Minute).Add(-4 * time.Minute)
	clients := make([]*agent.EvidenceClient, 0, len(f.tenants))
	for lane, tenant := range f.tenants {
		sender := gouuid.NewString()
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{ai.PermEntitiesRead, permMetricsRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := (store.Agents{}).Register(ctx, sc, sender, "DNS evidence sender",
				"127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, sender), nil); err != nil {
				return err
			}
			source := sameName
			if lane != 0 {
				source = "sibling-resolver"
			}
			return store.NewEntityRegistry(f.pool).AssignEntitySource(ctx, sc,
				entity.SourceKey{AgentID: sender, Kind: entity.DNSResolver, SourceRef: source}, f.contextID, f.routerID)
		})
		clients = append(clients, newSender(tenant, sender))
		// The synthetic aggregate windows are in the recent past. Preserve
		// their exact clocks while modeling an already-active assignment.
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET issued_at=$3
				WHERE tenant_id=$1 AND agent_id=$2`, tenant, sender, start.Add(-time.Minute)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts SET assigned_at=$3
				WHERE tenant_id=$1 AND agent_id=$2`, tenant, sender, start.Add(-time.Minute)); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=$3
				WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='dns_resolver'`, tenant, sender, start.Add(-time.Minute))
			return err
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	_, sender := clients[0].Identity()
	coveragePath := "/v1/entities/" + f.routerID + "/resolver-dns-coverage?" + (url.Values{
		"context_id": {f.contextID}, "agent_id": {sender}, "source_ref": {sameName},
	}).Encode()
	firstCoverage := callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, coveragePath, nil, http.StatusOK)
	if !bytes.Contains(firstCoverage, []byte("no_recent_capture")) {
		t.Fatal("unobserved resolver was presented as covered", string(firstCoverage))
	}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, coveragePath, nil, http.StatusNotFound)
	capture := resolverDNSFixture(start, 130, 70)
	rejected, err := clients[1].SubmitResolverDNS(t.Context(), sameName, capture)
	if rejected != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sibling assignment borrowed a foreign resolver: %+v, %v", rejected, err)
	}
	receipt, err := clients[0].SubmitResolverDNS(t.Context(), sameName, capture)
	if err != nil || receipt == nil || receipt.Intervals != 3 || receipt.PressureSignals != 1 {
		t.Fatalf("owned resolver pressure receipt: %+v, %v", receipt, err)
	}
	replay, err := clients[0].SubmitResolverDNS(t.Context(), sameName, capture)
	if err != nil || replay == nil || !bytes.Equal(replay.EvidenceDigest, receipt.EvidenceDigest) || replay.PressureSignals != 1 {
		t.Fatalf("exact receipt was not replayable: %+v, %v", replay, err)
	}
	conflict, err := clients[0].SubmitResolverDNS(t.Context(), sameName, resolverDNSFixture(start, 131, 70))
	if conflict != nil || status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed evidence horizontally reused the same capture clocks: %+v, %v", conflict, err)
	}
	quiet, err := clients[1].SubmitResolverDNS(t.Context(), "sibling-resolver", resolverDNSFixture(start, 1000, 2))
	if err != nil || quiet == nil || quiet.PressureSignals != 0 {
		t.Fatalf("ordinary sibling burst raised a pressure incident: %+v, %v", quiet, err)
	}
	published := callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, coveragePath, nil, http.StatusOK)
	if !bytes.Contains(published, []byte("missing_closed_file_intervals")) ||
		!bytes.Contains(published, []byte(`"client_responses":130`)) {
		t.Fatal("coverage omitted the measured minute or hid the gap", string(published))
	}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, coveragePath, nil, http.StatusNotFound)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var windows, responses int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),sum(client_responses)
				FROM resolver_dns_intervals WHERE minute_start >= $1`, start).Scan(&windows, &responses); err != nil {
				return err
			}
			expected := []int{390, 3000}[lane]
			if windows != 3 || responses != expected {
				t.Fatalf("tenant %d got %d windows and %d responses, expected 3 and %d", lane, windows, responses, expected)
			}
			incidents, err := (store.Incidents{}).OpenIncidents(ctx, sc)
			if err != nil {
				return err
			}
			if len(incidents) != 1-lane {
				t.Fatalf("tenant %d got %d resolver incidents", lane, len(incidents))
			}
			if lane == 0 {
				record, err := (store.Incidents{}).Get(ctx, sc, incidents[0].ID)
				if err != nil {
					return err
				}
				if len(record.Signals) != 1 || record.Signals[0].Kind != "dns.resolver.name_error_pressure" ||
					record.Signals[0].IdentityEntityID != f.routerID ||
					record.Signals[0].Attributes["dns.resolver.client_responses"] != "130" {
					t.Fatalf("pressure evidence was not attached to the exact resolver anchor: %+v", record.Signals)
				}
			}
			return nil
		})
	}
}

func resolverDNSFixture(at time.Time, responses, errors uint32) dnstap.ClosedCapture {
	capture := dnstap.ClosedCapture{Frames: responses * 3, Selected: responses * 3}
	for range 3 {
		end := at.Add(time.Minute)
		capture.Intervals = append(capture.Intervals, dnstap.ResolverIntervalCounts{
			From: at, To: end, Responses: responses, NameErrors: errors,
		})
		at = end
	}
	return capture
}
