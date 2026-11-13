// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestSNMPDescriptionOnlyDNSTargetUsesObservedPeerAndRefreshesChangedMetadata(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	inv := Inventory{Device: "forged-payload-address", SysDescr: "router OS",
		peerAddress: netip.MustParseAddr("192.0.2.7")}
	dev, now := Target{Address: "router.example"}, time.Now().UTC()
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now)
	if len(recorded.claims) != 1 || recorded.claims[0].Alias.Kind != entity.AddressAlias ||
		recorded.claims[0].Alias.Value != "192.0.2.7" || recorded.claims[0].Source.SourceRef != "router.example" ||
		recorded.claims[0].SourceRef != "snmp:configured-target" || recorded.claims[0].SystemDescription != "router OS" {
		t.Fatal("description-only DNS target lost its actual peer or invented a name/identity")
	}
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now.Add(time.Minute))
	if len(recorded.claims) != 1 {
		t.Fatal("unchanged metadata rewrote evidence on the next poll")
	}
	inv.SysDescr = "upgraded router OS"
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now.Add(2*time.Minute))
	if len(recorded.claims) != 2 || recorded.claims[1].SystemDescription != inv.SysDescr {
		t.Fatal("changed system description waited for the identity refresh interval")
	}
}

func TestMalformedSNMPSystemDescriptionDoesNotSuppressValidClaims(t *testing.T) {
	for _, description := range []string{"bad\x1bvalue", strings.Repeat("x", 1025), string([]byte{0xff})} {
		recorded := &recordedDeviceEvidence{}
		runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
			AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
			log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		runtime.emitSNMPEntityEvidence(context.Background(), Target{Address: "192.0.2.1"},
			Inventory{SysName: "edge-a", SysDescr: description}, nil, time.Now().UTC())
		if len(recorded.claims) != 2 || recorded.claims[0].SystemDescription != "" || recorded.claims[1].Alias.Value != "edge-a" ||
			recorded.claims[0].SystemName == nil || *recorded.claims[0].SystemName != "edge-a" {
			t.Fatal("malformed system description suppressed valid configured-target/name claims")
		}
	}
}

func TestSNMPRawSystemNameChangesAndClearsWithoutChangingIdentityNormalization(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := time.Now().UTC()
	for index, name := range []string{" edge-a ", "  edge-a  ", ""} {
		before := len(recorded.claims)
		runtime.emitSNMPEntityEvidence(t.Context(), Target{Address: "192.0.2.1"}, Inventory{SysName: name, SysDescr: "router OS"}, nil, now.Add(time.Duration(index)*time.Minute))
		claims := recorded.claims[before:]
		if len(claims) == 0 || claims[0].SystemName == nil || *claims[0].SystemName != name || claims[0].SystemDescription != "router OS" {
			t.Fatal("raw name change/clear suppressed by alias normalization or refresh interval")
		}
		if name == "" {
			if len(claims) != 1 {
				t.Fatal("empty raw name invented an identity alias")
			}
		} else if len(claims) != 2 || claims[1].Alias.Value != "edge-a" {
			t.Fatal("raw name changed canonical alias normalization")
		}
	}
}

func TestMalformedSNMPSystemNameDoesNotSuppressValidDescriptionOrAddress(t *testing.T) {
	for _, name := range []string{"bad\x1bvalue", strings.Repeat("x", 1025), string([]byte{0xff})} {
		recorded := &recordedDeviceEvidence{}
		runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
			AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
			log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		runtime.emitSNMPEntityEvidence(t.Context(), Target{Address: "192.0.2.1"}, Inventory{SysName: name, SysDescr: "valid OS"}, nil, time.Now().UTC())
		if len(recorded.claims) != 1 || recorded.claims[0].Alias.Value != "192.0.2.1" ||
			recorded.claims[0].SystemDescription != "valid OS" || recorded.claims[0].SystemName != nil {
			t.Fatal("malformed name suppressed another valid source fact")
		}
	}
}

type recordedDeviceEvidence struct {
	claims     []entity.Observation
	faults     []entity.FaultObservation
	unresolved int
	onSubmit   func()
	faultErr   error
}

func (r *recordedDeviceEvidence) SubmitFault(_ context.Context, fault entity.FaultObservation) error {
	r.faults = append(r.faults, fault)
	return r.faultErr
}

func TestFailedSNMPPollSendsSenderBoundFaultWithoutInventingContext(t *testing.T) {
	const agentID = "22222222-2222-4222-8222-222222222222"
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: agentID}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dialSNMP: func(Target, Credential) (snmpConn, error) {
			return nil, errors.New("device unreachable")
		}}
	runtime.pollOnce(context.Background(), Target{Address: "10.42.0.1"}, Credential{})
	if len(recorded.faults) != 1 {
		t.Fatalf("failed poll fault count=%d, want one", len(recorded.faults))
	}
	fault := recorded.faults[0]
	if fault.Source.AgentID != agentID || fault.Source.Kind != entity.DeviceTarget ||
		fault.Source.SourceRef != "10.42.0.1" || fault.Target != "10.42.0.1" ||
		fault.Kind != entity.FaultDevicePollFailed || fault.ID == "" {
		t.Fatalf("poll failure forged or lost configured sender evidence: %+v", fault)
	}
	runtime.pollOnce(context.Background(), Target{Address: "10.42.0.1"}, Credential{})
	if len(recorded.faults) != 1 {
		t.Fatal("continuing failed poll generated a new durable fault every cycle")
	}
	runtime.pollOnce(context.Background(), Target{Address: "router.internal"}, Credential{})
	if len(recorded.faults) != 1 {
		t.Fatal("non-IP device target fabricated a canonical fault address")
	}
	runtime.clearSNMPFault("10.42.0.1")
	runtime.pollOnce(context.Background(), Target{Address: "10.42.0.1"}, Credential{})
	if len(recorded.faults) != 2 || recorded.faults[1].ID == fault.ID {
		t.Fatal("recovered and failed device reused the previous outage UUID")
	}
}

func TestDeviceFaultLostResponseRetriesSameUUID(t *testing.T) {
	recorded := &recordedDeviceEvidence{faultErr: errors.New("lost response")}
	runtime := &Runtime{cfg: &Config{TenantID: "tenant-a", AgentID: "device-agent-a"},
		evidence: recorded, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dev := Target{Address: "10.42.0.1"}
	at := time.Now().UTC()
	runtime.emitSNMPFault(context.Background(), dev, at)
	runtime.emitSNMPFault(context.Background(), dev, at.Add(time.Minute))
	if len(recorded.faults) != 2 || recorded.faults[0].ID != recorded.faults[1].ID ||
		!recorded.faults[0].ObservedAt.Equal(recorded.faults[1].ObservedAt) {
		t.Fatalf("lost response created a second fault identity: %+v", recorded.faults)
	}
	recorded.faultErr = nil
	runtime.emitSNMPFault(context.Background(), dev, at.Add(2*time.Minute))
	runtime.emitSNMPFault(context.Background(), dev, at.Add(3*time.Minute))
	if len(recorded.faults) != 3 || recorded.faults[2].ID != recorded.faults[0].ID ||
		len(runtime.faultPending) != 0 {
		t.Fatalf("successful replay did not close its pending receipt: %+v", recorded.faults)
	}
}

func TestDeviceEvidenceRequiresRenewalEndpoint(t *testing.T) {
	cfg := EvidenceConfig{ControlAddr: "control:9443", CertFile: "entity/cert.pem",
		KeyFile: "entity/key.pem", CAFile: "entity/server-ca.pem"}
	if err := cfg.validate(); err == nil {
		t.Fatal("accepted short-lived evidence certificate without renewal")
	}
	cfg.RotateURL = "https://control:8443"
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
}

func (r *recordedDeviceEvidence) Submit(_ context.Context, items []entity.Observation) (int, int, error) {
	r.claims = append(r.claims, items...)
	if r.onSubmit != nil {
		r.onSubmit()
	}
	return len(items) - r.unresolved, r.unresolved, nil
}

func TestSNMPEvidenceUsesConfiguredSourceNotPacketRouting(t *testing.T) {
	const agentID = "22222222-2222-4222-8222-222222222222"
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: agentID}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	inv := Inventory{Device: "203.0.113.99", SysName: "router-a", SysDescr: "router OS",
		Interfaces: map[uint32]Interface{7: {Index: 7, Name: "xe-0/0/7", Descr: "uplink", Addrs: []netip.Addr{
			netip.MustParseAddr("10.42.0.1"),
			netip.MustParseAddr("2001:db8::1"),
		}}}}
	runtime.emitSNMPEntityEvidence(context.Background(), Target{Address: "192.0.2.1"},
		inv, []NeighborEvidence{{Protocol: NeighborProtocolLLDP, LocalIfIndex: 7,
			LocalPortID: "xe-0/0/7", RemotePortID: "xe-0/0/8",
			RemoteChassisID: "00:11:22:33:44:55", RemoteDeviceName: "router-b",
			RemoteManagementAddress: "10.42.0.2"}}, time.Now().UTC())
	if len(recorded.claims) != 6 {
		t.Fatalf("got %d source claims, want configured target, sysName, interface ID, two addresses and LLDP", len(recorded.claims))
	}
	for _, claim := range recorded.claims {
		if claim.Source.AgentID != agentID || claim.Source.Kind != entity.DeviceTarget ||
			claim.Source.SourceRef != "192.0.2.1" || claim.ID == "" {
			t.Fatalf("SNMP packet selected routing source: %+v", claim)
		}
	}
	if recorded.claims[0].Alias.Value != "192.0.2.1" ||
		recorded.claims[2].Alias.Kind != entity.SNMPInterfaceAlias ||
		recorded.claims[2].Alias.Value != "7" ||
		recorded.claims[2].InterfaceName != "xe-0/0/7" ||
		recorded.claims[2].InterfaceDescription != "uplink" ||
		recorded.claims[0].SystemDescription != "router OS" ||
		recorded.claims[3].Alias.Value != "10.42.0.1" ||
		recorded.claims[4].Alias.Value != "2001:db8::1" ||
		recorded.claims[5].Alias.Kind != entity.PhysicalNeighborAlias ||
		recorded.claims[5].NeighborLocalIfIndex != 7 ||
		recorded.claims[5].NeighborRemotePortID != "xe-0/0/8" ||
		recorded.claims[5].NeighborAddress != "10.42.0.2" {
		t.Fatalf("configured and interface addresses lost: %+v", recorded.claims)
	}
}

func TestSNMPInterfaceStateChangesBypassIdentityRefreshAndKeepAbsence(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	inv := Inventory{Interfaces: map[uint32]Interface{7: {Index: 7, Name: "wan", OperStatus: 1, AdminStatus: 1}}}
	now := time.Now().UTC()
	emit := func() {
		t.Helper()
		runtime.emitSNMPEntityEvidence(t.Context(), Target{Address: "192.0.2.1"}, inv, nil, now)
	}
	emit()
	if len(recorded.claims) != 2 || recorded.claims[1].SNMPInterfaceState == nil || *recorded.claims[1].SNMPInterfaceState.OperStatus != 1 || *recorded.claims[1].SNMPInterfaceState.AdminStatus != 1 {
		t.Fatal("actual interface state did not accompany its configured source")
	}
	emit()
	if len(recorded.claims) != 2 {
		t.Fatal("unchanged state appended one receipt per poll")
	}
	for _, state := range []Interface{{Index: 7, Name: "wan", OperStatus: 7, AdminStatus: 1}, {Index: 7, Name: "wan", OperStatus: 7, AdminStatus: 2}, {Index: 7, Name: "wan"}} {
		before := len(recorded.claims)
		inv.Interfaces[7] = state
		emit()
		if len(recorded.claims) != before+2 || recorded.claims[before+1].Alias.Kind != entity.SNMPInterfaceAlias || recorded.claims[before+1].Source.SourceRef != "192.0.2.1" {
			t.Fatal("changed state waited for the identity refresh or lost source binding")
		}
		got := recorded.claims[before+1].SNMPInterfaceState
		if state.OperStatus == 0 {
			if got != nil {
				t.Fatal("unavailable state inherited the previous observation")
			}
		} else if got == nil || *got.OperStatus != state.OperStatus || *got.AdminStatus != state.AdminStatus {
			t.Fatal("state transition changed original enums")
		}
	}
	if *recorded.claims[1].SNMPInterfaceState.OperStatus != 1 || *recorded.claims[1].SNMPInterfaceState.AdminStatus != 1 {
		t.Fatal("later poll rewrote an earlier observation")
	}
}

func TestMalformedSNMPInterfaceLabelDoesNotPoisonEvidenceBatch(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	inv := Inventory{SysName: "edge-a", Interfaces: map[uint32]Interface{
		7: {Index: 7, Name: "invalid\nname", Addrs: []netip.Addr{
			netip.MustParseAddr("10.42.0.1")}},
	}}
	runtime.emitSNMPEntityEvidence(context.Background(), Target{Address: "192.0.2.1"},
		inv, nil, time.Now().UTC())
	if len(recorded.claims) != 3 {
		t.Fatalf("malformed interface label suppressed valid target/name/address: %+v", recorded.claims)
	}
	for _, claim := range recorded.claims {
		if claim.Alias.Kind == entity.SNMPInterfaceAlias {
			t.Fatalf("malformed interface label entered evidence batch: %+v", claim)
		}
		if _, err := claim.Normalize(claim.ObservedAt); err != nil {
			t.Fatalf("sender queued invalid evidence observation: %+v: %v", claim, err)
		}
	}
}

func TestStableSNMPIdentityRefreshesWithoutOneRowPerPoll(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dev := Target{Address: "192.0.2.1"}
	inv := Inventory{SysName: "edge-a", Interfaces: map[uint32]Interface{
		7: {Index: 7, Name: "xe-0/0/7", Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.1")}},
	}}
	neighbor := []NeighborEvidence{{Protocol: NeighborProtocolLLDP, LocalIfIndex: 7,
		LocalPortID: "xe-0/0/7", RemotePortID: "xe-0/0/8",
		RemoteDeviceName: "edge-b", RemoteManagementAddress: "10.42.0.2"}}
	now := time.Now().UTC()
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, neighbor, now)
	first := len(recorded.claims)
	if first != 5 {
		t.Fatalf("initial identity claims=%d, want target, name, interface, IP, LLDP", first)
	}
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, neighbor, now.Add(time.Minute))
	if len(recorded.claims) != first {
		t.Fatal("unchanged one-minute poll wrote duplicate durable identity evidence")
	}
	changed := inv
	changed.Interfaces = map[uint32]Interface{7: {Index: 7, Name: "xe-0/0/7-renamed",
		Addrs: []netip.Addr{netip.MustParseAddr("10.42.0.1")}}}
	runtime.emitSNMPEntityEvidence(context.Background(), dev, changed, neighbor, now.Add(2*time.Minute))
	if len(recorded.claims) != first*2 {
		t.Fatal("changed SNMP identity was held behind the refresh interval")
	}
}

func TestPartlyUnresolvedSNMPSnapshotDoesNotRewriteAcceptedAliasEachPoll(t *testing.T) {
	recorded := &recordedDeviceEvidence{unresolved: 1}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dev := Target{Address: "192.0.2.1"}
	inv := Inventory{SysName: "edge-a"}
	now := time.Now().UTC()
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now)
	if len(recorded.claims) != 2 {
		t.Fatalf("initial claims = %d, want target and sysName", len(recorded.claims))
	}
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now.Add(time.Minute))
	if len(recorded.claims) != 2 {
		t.Fatal("unchanged partially accepted inventory rewrote accepted evidence on the next poll")
	}
	snapshot := runtime.evidenceLast[dev.Address]
	snapshot.retryAt = time.Now().Add(-entityEvidenceUnresolvedRetry)
	runtime.evidenceLast[dev.Address] = snapshot
	recorded.unresolved = 0
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now.Add(2*time.Minute))
	if len(recorded.claims) != 4 || runtime.evidenceLast[dev.Address].sentAt.IsZero() {
		t.Fatal("unresolved identity did not retry after bounded interval")
	}
}

func TestWhollyUnresolvedSNMPSnapshotRetriesNextPoll(t *testing.T) {
	recorded := &recordedDeviceEvidence{unresolved: 1}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dev := Target{Address: "192.0.2.1"}
	now := time.Now().UTC()
	runtime.emitSNMPEntityEvidence(context.Background(), dev, Inventory{}, nil, now)
	if len(recorded.claims) != 1 {
		t.Fatalf("initial unresolved claims = %d, want one", len(recorded.claims))
	}
	recorded.unresolved = 0
	runtime.emitSNMPEntityEvidence(context.Background(), dev, Inventory{}, nil, now.Add(time.Minute))
	if len(recorded.claims) != 2 || runtime.evidenceLast[dev.Address].sentAt.IsZero() {
		t.Fatal("wholly unresolved SNMP evidence did not retry on next poll")
	}
}

func TestDeviceEvidenceRotationDuringSubmitCannotRestoreOldThrottle(t *testing.T) {
	recorded := &recordedDeviceEvidence{}
	runtime := &Runtime{cfg: &Config{TenantID: "11111111-1111-4111-8111-111111111111",
		AgentID: "22222222-2222-4222-8222-222222222222"}, evidence: recorded,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	recorded.onSubmit = func() {
		recorded.onSubmit = nil
		runtime.RefreshEvidenceAfterRotation()
	}
	dev := Target{Address: "192.0.2.1"}
	inv := Inventory{SysName: "edge-a"}
	now := time.Now().UTC()
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now)
	if len(recorded.claims) != 2 {
		t.Fatalf("first evidence batch=%d, want two claims", len(recorded.claims))
	}
	runtime.emitSNMPEntityEvidence(context.Background(), dev, inv, nil, now.Add(time.Minute))
	if len(recorded.claims) != 4 || runtime.evidenceLast[dev.Address].sentAt.IsZero() {
		t.Fatal("in-flight old certificate response suppressed fresh post-rotation evidence")
	}
}
