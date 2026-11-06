// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

type fakeBMPEvidence struct{}

func (fakeBMPEvidence) Submit(_ context.Context, items []entity.Observation) (int, int, error) {
	return len(items), 0, nil
}

type unresolvedBMPEvidence struct{ calls chan int }

func (e unresolvedBMPEvidence) Submit(_ context.Context, claims []entity.Observation) (int, int, error) {
	e.calls <- len(claims)
	return 0, len(claims), nil
}

func TestWhollyUnresolvedBMPEvidenceRetriesAfterOneMinute(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	base := time.Now().UTC()
	var clockNanos atomic.Int64
	clockNanos.Store(base.UnixNano())
	calls := make(chan int, 2)
	l := NewBMPListener(nil, nil, "", nil,
		WithBMPTenantLane(tenant, "tenant-lane"),
		WithBMPEntityEvidence("listener-auth", unresolvedBMPEvidence{calls: calls}))
	l.now = func() time.Time { return time.Unix(0, clockNanos.Load()) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.evidenceLoop(ctx) }()
	defer func() { cancel(); <-done }()
	peer := bmpPeerEvidence{tenantID: tenant, routerAgentID: "router-auth",
		routerSerial: "ab1234", peerAddress: "192.0.2.7", peerASN: 64500,
		observedAt: base}
	send := func() {
		t.Helper()
		l.queuePeerEvidence(peer)
		select {
		case count := <-calls:
			if count != 2 {
				t.Fatalf("unresolved BMP claims = %d, want address and peer", count)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("wholly unresolved BMP evidence did not retry")
		}
	}
	send()
	clockNanos.Store(base.Add(bmpEvidenceRetry).UnixNano())
	peer.observedAt = base.Add(bmpEvidenceRetry)
	send()
}

func TestBMPEvidenceUsesAuthenticatedRouterAndListenerLane(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	l := NewBMPListener(nil, nil, "", nil,
		WithBMPTenantLane(tenant, "tenant-lane"),
		WithBMPEntityEvidence("listener-auth", fakeBMPEvidence{}))
	peer := bmpPeerEvidence{tenantID: tenant, routerAgentID: "router-auth",
		routerSerial: "ab1234", peerAddress: "192.0.2.7",
		peerASN: 64500, observedAt: time.Now().UTC()}
	claims, err := l.peerEvidenceClaims(peer)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	for _, claim := range claims {
		if claim.Source != (entity.SourceKey{AgentID: "listener-auth",
			Kind: entity.BMPPeer, SourceRef: "router-auth"}) || claim.ID == "" {
			t.Fatalf("BMP peer header selected source: %+v", claim)
		}
		if _, err := claim.Normalize(time.Now()); err != nil {
			t.Fatalf("invalid evidence claim: %v", err)
		}
	}
	if claims[0].Alias != (entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.7"}) ||
		claims[1].Alias != (entity.AliasKey{Kind: entity.BMPPeerAlias, Value: "192.0.2.7/as64500"}) {
		t.Fatalf("peer aliases = %+v", claims)
	}
	peer.tenantID = "33333333-3333-4333-8333-333333333333"
	if _, err := l.peerEvidenceClaims(peer); err == nil {
		t.Fatal("cross-tenant peer evidence accepted")
	}
	l.queuePeerEvidence(peer)
	if got := len(l.evidenceQueue); got != 0 {
		t.Fatalf("cross-tenant peer entered queue: %d", got)
	}
}

func TestBMPEvidenceStablePeerDoesNotWriteOnEveryRoute(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name  string
		state bmpEvidenceAttempt
		wait  time.Duration
		want  bool
	}{
		{"first peer", bmpEvidenceAttempt{}, 0, true},
		{"accepted next minute", bmpEvidenceAttempt{acceptedAt: now, attemptAt: now}, time.Minute, false},
		{"accepted refresh", bmpEvidenceAttempt{acceptedAt: now, attemptAt: now}, bmpEvidenceRefresh, true},
		{"partial next minute", bmpEvidenceAttempt{partialAt: now, attemptAt: now}, time.Minute, false},
		{"partial retry", bmpEvidenceAttempt{partialAt: now, attemptAt: now}, bmpEvidenceUnresolvedRetry, true},
		{"transport next second", bmpEvidenceAttempt{attemptAt: now}, time.Second, false},
		{"transport retry", bmpEvidenceAttempt{attemptAt: now}, bmpEvidenceRetry, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.due(now.Add(tc.wait)); got != tc.want {
				t.Fatalf("due after %s = %v, want %v", tc.wait, got, tc.want)
			}
		})
	}
}

type capturedBMPEvidence struct{ calls chan []entity.Observation }

func (c capturedBMPEvidence) Submit(_ context.Context, claims []entity.Observation) (int, int, error) {
	c.calls <- claims
	return len(claims), 0, nil
}

func TestBMPEvidenceReconnectRestatesCurrentPeersWithoutPerRouteWrites(t *testing.T) {
	calls := make(chan []entity.Observation, 8)
	stack := startBMPTestStack(t, WithBMPTenantLane("tenant-a", "tenant-a-lane"), WithBMPEntityEvidence("listener-auth", capturedBMPEvidence{calls: calls}))
	defer stack.stop()
	cert, key, _ := stack.issue("tenant-a", "router-a", time.Hour)
	conn, err := stack.dial(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	frame := buildBMPRouteMonitoring(64500, "192.0.2.7", []uint32{64500}, "203.0.113.0/24", time.Now())
	write := func(raw []byte) {
		t.Helper()
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(marker string) []entity.Observation {
		t.Helper()
		select {
		case got := <-calls:
			return got
		case <-time.After(5 * time.Second):
			t.Fatal(marker)
			return nil
		}
	}
	write(frame)
	first := receive("first authenticated BMP peer did not publish evidence")
	if len(first) != 2 || first[1].Alias.Value != "192.0.2.7/as64500" {
		t.Fatal("authenticated BMP peer claim changed", first)
	}
	for range 3 {
		write(frame)
	}
	// The worker's FIFO barrier proves all repeated routes were consumed. Only
	// this different peer may publish before the same-credential reconnection.
	write(buildBMPRouteMonitoring(64501, "192.0.2.8", []uint32{64501}, "198.51.100.0/24", time.Now()))
	barrier := receive("BMP evidence worker did not process its peer barrier")
	if len(barrier) != 2 || barrier[1].Alias.Value != "192.0.2.8/as64501" {
		t.Fatal("stable BMP peer wrote on every unchanged route", barrier)
	}
	_ = conn.Close()
	conn, err = stack.dial(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	write(frame)
	renewed := receive("fresh authenticated BMP session reused old peer evidence suppression")
	if len(renewed) != 2 || renewed[1].Alias != first[1].Alias || renewed[1].Source != first[1].Source || renewed[1].OriginSerial != first[1].OriginSerial || renewed[1].ID == first[1].ID || !renewed[1].ObservedAt.After(first[1].ObservedAt) {
		t.Fatal("reconnected BMP peer did not restate same owned source with a new observation", renewed)
	}
}
