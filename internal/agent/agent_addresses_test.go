// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestAgentInterfaceSnapshotUsesAllHostIPsWithoutNetworkOrHostnameInference(t *testing.T) {
	got, err := localAgentAddresses([]net.Addr{&net.IPNet{IP: net.ParseIP("10.2.0.7"), Mask: net.CIDRMask(24, 32)}, &net.IPAddr{IP: net.ParseIP("2001:db8::9")}, &net.IPAddr{IP: net.ParseIP("10.2.0.7")}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}, &net.IPAddr{IP: net.IPv4zero}, &net.IPAddr{IP: net.ParseIP("ff02::1")}})
	if err != nil || len(got) != 4 || got[0].String() != "10.2.0.7" {
		t.Fatalf("complete local host snapshot: %v %v", got, err)
	}
	if clear, err := localAgentAddresses(nil); err != nil || clear == nil || len(clear) != 0 {
		t.Fatal("successful empty collection lost presence")
	}
	if _, err := localAgentAddresses([]net.Addr{&net.IPAddr{}}); err == nil {
		t.Fatal("collection failure became a complete empty snapshot")
	}
}

func TestAgentSiteWorkerPublishesOnlyAddressTransitionsClearFailureAndRotation(t *testing.T) {
	var mode, calls atomic.Int32
	a := &Agent{cfg: &Config{Agent: Meta{Labels: map[string]string{"site": "dub-1"}}}, tenantID: "11111111-1111-4111-8111-111111111111", agentID: "22222222-2222-4222-8222-222222222222", log: slog.New(slog.NewTextHandler(io.Discard, nil)), sitePollInterval: time.Millisecond * 5}
	a.siteAddresses = func() ([]netip.Addr, error) {
		calls.Add(1)
		switch mode.Load() {
		case 1:
			return []netip.Addr{netip.MustParseAddr("2001:db8::9")}, nil
		case 2:
			return nil, errors.New("planted collection failure")
		case 3:
			return []netip.Addr{}, nil
		default:
			return []netip.Addr{netip.MustParseAddr("10.2.0.7")}, nil
		}
	}
	claims := make(chan entity.Observation, 64)
	a.WithSiteEvidence(captureSiteEvidence{claims: claims})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { a.runSiteEvidence(ctx); close(done) }()
	read := func() entity.Observation {
		t.Helper()
		select {
		case item := <-claims:
			return item
		case <-time.After(time.Second):
			t.Fatal("worker did not publish a changed snapshot")
			return entity.Observation{}
		}
	}
	quiet := func() {
		t.Helper()
		target := calls.Load() + 3
		deadline := time.After(time.Second)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for calls.Load() < target {
			select {
			case <-deadline:
				t.Fatal("local polling stopped")
			case <-ticker.C:
			}
		}
		select {
		case <-claims:
			t.Fatal("unchanged local snapshot wrote another evidence row")
		default:
		}
	}
	first := read()
	if len(first.AgentAddresses) != 1 || first.AgentAddresses[0].String() != "10.2.0.7" {
		t.Fatal("first snapshot missing host fact")
	}
	quiet()
	mode.Store(1)
	if next := read(); len(next.AgentAddresses) != 1 || next.AgentAddresses[0].String() != "2001:db8::9" {
		t.Fatal("changed interface address was not published")
	}
	mode.Store(2)
	if next := read(); next.AgentAddresses != nil {
		t.Fatal("failed collection fabricated complete addresses")
	}
	quiet()
	mode.Store(3)
	if next := read(); next.AgentAddresses == nil || len(next.AgentAddresses) != 0 {
		t.Fatal("empty complete snapshot lost its explicit clear")
	}
	mode.Store(0)
	restored := read()
	if len(restored.AgentAddresses) != 1 {
		t.Fatal("collection recovery did not restore complete facts")
	}
	a.RefreshSiteEvidenceAfterRotation()
	rotated := read()
	if rotated.ID == restored.ID || len(rotated.AgentAddresses) != 1 {
		t.Fatal("rotation did not attest a new complete claim")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("address worker ignored cancellation")
	}
}

func TestAgentAddressEvidenceWireRetainsLegacyClearAndHostSets(t *testing.T) {
	c := &EvidenceClient{agentID: "agent", svc: agentv1.NewAgentServiceClient(nil)}
	now := time.Now().UTC()
	for _, addresses := range [][]netip.Addr{nil, {}, {netip.MustParseAddr("10.2.0.7"), netip.MustParseAddr("2001:db8::9")}} {
		item := entity.Observation{ID: "33333333-3333-4333-8333-333333333333", Source: entity.SourceKey{AgentID: "agent", Kind: entity.AgentSite, SourceRef: "agent"}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "dub-1"}, SourceRef: "agent:label:site", ObservedAt: now, AgentAddresses: addresses}
		req, err := c.encodeEvidence(now, []entity.Observation{item})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := proto.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		var decoded agentv1.SubmitEntityEvidenceRequest
		if err := proto.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		wire := decoded.Observations[0].AgentAddresses
		if (wire == nil) != (addresses == nil) {
			t.Fatal("protobuf erased metadata presence")
		}
		if wire != nil {
			got, err := entity.ParseAgentAddressSnapshot(wire.Addresses)
			if err != nil || len(got) != len(addresses) {
				t.Fatal("wire snapshot lost the complete set")
			}
		}
	}
}

func TestAgentAddressEvidenceWireRefusesWholeBatchByteOverflow(t *testing.T) {
	client := &EvidenceClient{agentID: "agent", svc: agentv1.NewAgentServiceClient(nil)}
	addresses := make([]netip.Addr, 50000)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	now := time.Now().UTC()
	item := entity.Observation{ID: "33333333-3333-4333-8333-333333333333", Source: entity.SourceKey{AgentID: "agent", Kind: entity.AgentSite, SourceRef: "agent"}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "dub-1"}, SourceRef: "agent:label:site", ObservedAt: now, AgentAddresses: addresses}
	if req, err := client.encodeEvidence(now, []entity.Observation{item}); err != nil || proto.Size(req) > 1<<20 {
		t.Fatal("one complete in-budget snapshot refused")
	}
	second := item
	second.ID = "44444444-4444-4444-8444-444444444444"
	if _, err := client.encodeEvidence(now, []entity.Observation{item, second}); !errors.Is(err, ErrEvidenceBatchInvalid) {
		t.Fatal("combined message overflow was truncated or sent")
	}
}
