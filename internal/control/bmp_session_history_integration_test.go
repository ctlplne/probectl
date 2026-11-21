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
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

const (
	bmpHistoryFixtureCollector = "role-listener"
	bmpHistoryFixtureSource    = "role-router"
	bmpHistoryFixturePeer      = "192.0.2.7"
)

func seedBMPSessionHistoryAPI(t *testing.T, f *roleExplanationAPIFixture) {
	t.Helper()
	budget := bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	connection := gouuid.NewString()
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAIQuery)
		})
		frame := make([]byte, 64)
		frame[0], frame[5] = 3, 1
		binary.BigEndian.PutUint32(frame[1:5], uint32(len(frame)))
		copy(frame[28:32], []byte{192, 0, 2, 7})
		binary.BigEndian.PutUint32(frame[32:36], 64496)
		binary.BigEndian.PutUint32(frame[48:52], 1)
		binary.BigEndian.PutUint16(frame[52:54], 18)
		binary.BigEndian.PutUint16(frame[54:56], 8)
		binary.BigEndian.PutUint64(frame[56:], math.MaxUint64-uint64(lane))
		input := store.BMPSessionEvidenceInput{CollectorAgentID: bmpHistoryFixtureCollector, SourceRef: bmpHistoryFixtureSource,
			SenderSerial: f.serials[tenant+bmpHistoryFixtureCollector], OriginSerial: f.serials[tenant+bmpHistoryFixtureSource],
			ConnectionID: connection, ObservedAt: f.observedAt(tenant), Sequence: 1, Frame: frame}
		copy(input.Digest[:], crypto.Hash(frame))
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := store.RecordBMPSessionEvidenceInScope(ctx, sc, input, budget, store.BMPSessionSignalPolicy{}); err != nil {
					return err
				}
				closed := input
				closed.Frame, closed.Sequence, closed.TransportClosed = nil, 2, true
				copy(closed.Digest[:], crypto.Hash([]byte("fixture transport close")))
				_, err := store.RecordBMPSessionEvidenceInScope(ctx, sc, closed, budget, store.BMPSessionSignalPolicy{})
				return err
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func bmpHistoryFixturePath(f *roleExplanationAPIFixture) string {
	args := url.Values{"context_id": {f.contextID}, "collector_agent_id": {bmpHistoryFixtureCollector}, "source_ref": {bmpHistoryFixtureSource}}
	return "/v1/bgp/sessions/" + f.routerID + "?" + args.Encode()
}

func TestBMPSessionHistoryServesPairedExactCountersAndNativeRedaction(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	seedBMPSessionHistoryAPI(t, f)
	seedInterfaceRoleMCPConsent(f)
	ca := filepath.Join(t.TempDir(), "bmp-history-api-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	path := bmpHistoryFixturePath(f)
	for lane, tenant := range f.tenants {
		base := path + "&peer=" + bmpHistoryFixturePeer + "&statistic=18&expected_min=18446744073709551615&expected_max=18446744073709551615"
		var first, last bmpSessionHistoryPage
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, base+"&limit=1", nil, http.StatusOK)
		if err := json.Unmarshal(raw, &first); err != nil || first.NextCursor == "" || len(first.Items) != 1 || !first.Items[0].CoverageGap {
			t.Fatal("REST lost disconnect gap and same-clock continuation", err)
		}
		raw = callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path+"&cursor="+url.QueryEscape(first.NextCursor), nil, http.StatusOK)
		want := math.MaxUint64 - uint64(lane)
		status := "within_range"
		if lane == 1 {
			status = "below_range"
		}
		if err := json.Unmarshal(raw, &last); err != nil || len(last.Items) != 1 || last.Items[0].Statistics == nil ||
			last.Items[0].Statistics.Samples[0].Value != want || last.Items[0].Nanos != first.Items[0].Nanos || last.Items[0].RangeStatus != status {
			t.Fatal("REST crossed tenant gauge or lost exact expected range", err)
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		args := []string{"--json", "bgp", "session-history", f.routerID, "--query", "context_id=" + f.contextID,
			"--query", "collector_agent_id=" + bmpHistoryFixtureCollector, "--query", "source_ref=" + bmpHistoryFixtureSource}
		if code := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), strconv.FormatUint(want, 10)) {
			t.Fatal("shipped CLI lost the scoped original BMP value", code)
		}
	}
	for _, wire := range []string{"2025-11-25", "2026-07-28"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			args := map[string]any{"router_id": f.routerID, "context_id": f.contextID, "collector_agent_id": bmpHistoryFixtureCollector,
				"source_ref": bmpHistoryFixtureSource, "peer": bmpHistoryFixturePeer, "limit": 1}
			var first struct {
				Next string `json:"next_cursor"`
			}
			call(tenant, "bgp_session_history", args, &first, true)
			if first.Next == "" {
				t.Fatal("native BMP history continuation missing", wire)
			}
			args["cursor"] = first.Next
			var raw json.RawMessage
			call(tenant, "bgp_session_history", args, &raw, true)
			if bytes.Contains(raw, []byte(bmpHistoryFixturePeer)) || bytes.Contains(raw, []byte(bmpHistoryFixtureSource)) {
				t.Fatal("native history exposed private address or configured source text", wire)
			}
			var page bmpSessionHistoryPage
			if err := json.Unmarshal(raw, &page); err != nil || len(page.Items) != 1 || page.Items[0].Statistics == nil ||
				page.Items[0].Statistics.Samples[0].Value != math.MaxUint64-uint64(lane) {
				t.Fatal("native history lost the exactly scoped gauge", wire, err)
			}
		}
	}
	revoked := f.tenants[0]
	if _, _, err := store.NewAgentIdentities(f.pool).RevokeAgent(t.Context(), revoked, bmpHistoryFixtureSource, f.users[revoked]); err != nil {
		t.Fatal(err)
	}
	callSeasonalAPI(t, socket, f.tokens[revoked], http.MethodGet, path, nil, http.StatusNotFound)
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusOK)
}

func TestBMPSessionHistoryBrowserKeepsBothTenantGaugesAndUnknownClosure(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	seedBMPSessionHistoryAPI(t, f)
	ca := filepath.Join(t.TempDir(), "bmp-history-ui-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/bgp",
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{
						{Click: "Open session history"},
						{Fill: "input[name=router_id]", Value: f.routerID},
						{Fill: "input[name=context_id]", Value: f.contextID},
						{Fill: "input[name=collector_agent_id]", Value: bmpHistoryFixtureCollector},
						{Fill: "input[name=source_ref]", Value: bmpHistoryFixtureSource},
						{Click: "Load session history", ExpectWithin: "table:has(caption:text-is('BMP session history'))",
							Expect: []string{strconv.FormatUint(math.MaxUint64-uint64(lane), 10), "Peer state is unknown after disconnect", "Observation gap"},
							Absent: []string{strconv.FormatUint(math.MaxUint64-uint64(1-lane), 10)}},
					},
				})
			})
		}
	}
}

func TestBMPSessionHistoryServesScopedLossAndFlapWithGapOmission(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	writer := BMPSessionSignalWriter(time.Minute, f.server.log, nil)
	policy := store.BMPSessionSignalPolicy{LossEnabled: true, FlapThreshold: 2, FlapWindow: 5 * time.Minute}
	up := internetPhysicalUpForTest(64500, 64496)
	down := append(append([]byte(nil), up[:48]...), 4)
	down[5] = 2
	binary.BigEndian.PutUint32(down[1:5], uint32(len(down)))
	withdrawn := append([]byte(nil), down...)
	withdrawn[48] = 5
	connection := gouuid.NewString()
	for _, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		at := f.observedAt(tenant)
		for _, point := range []struct {
			sequence int64
			frame    []byte
			signals  int
		}{{1, up, 0}, {2, down, 1}, {3, up, 0}, {4, down, 2}, {4, down, 0},
			{6, up, 0}, {7, down, 0}, {8, withdrawn, 0}} {
			input := store.BMPSessionEvidenceInput{CollectorAgentID: bmpHistoryFixtureCollector, SourceRef: bmpHistoryFixtureSource,
				SenderSerial: f.serials[tenant+bmpHistoryFixtureCollector], OriginSerial: f.serials[tenant+bmpHistoryFixtureSource],
				ConnectionID: connection, ObservedAt: at, Sequence: point.sequence, Frame: point.frame}
			copy(input.Digest[:], crypto.Hash(point.frame))
			err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error {
				return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					result, err := store.RecordBMPSessionEvidenceInScope(ctx, sc, input, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}, policy)
					if err != nil {
						return err
					}
					if len(result.Signals) != point.signals || result.CoverageGap != (point.sequence == 6) {
						return fmt.Errorf("discontinuous or repeated evidence changed detection for sequence %d", point.sequence)
					}
					_, err = writer(ctx, sc, result.Signals)
					return err
				})
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var losses, flaps, incidents int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='bgp.session_loss'),
 count(*) FILTER (WHERE kind='bgp.session_flap'),count(DISTINCT incident_id)
 FROM incident_signals WHERE attributes->>'probectl.bgp.bmp.connection_id'=$1`, connection).Scan(&losses, &flaps, &incidents); err != nil {
				return err
			}
			if losses != 2 || flaps != 1 || incidents != 1 {
				return fmt.Errorf("the paired scope lost or duplicated a session finding")
			}
			return nil
		})
	}
}
