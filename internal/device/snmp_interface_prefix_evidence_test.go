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
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/gosnmp/gosnmp"
)

// Real pollOnce path, modeled SNMP packets and evidence sink. Current sender,
// storage and real-router acceptance are separate mandatory integration proof.
type prefixPollConn struct {
	*fakeConn
	prefix *snmpPrefixSnapshotConn
}

func (c *prefixPollConn) walkInterfacePrefixes(ctx context.Context, fn gosnmp.WalkFunc) error {
	return c.prefix.walkInterfacePrefixes(ctx, fn)
}

type prefixPollEvidence struct {
	recordedDeviceEvidence
	batches [][]entity.Observation
}

func (r *prefixPollEvidence) Submit(ctx context.Context, items []entity.Observation) (int, int, error) {
	r.batches = append(r.batches, slices.Clone(items))
	return r.recordedDeviceEvidence.Submit(ctx, items)
}

func prefixPollRuntime(t *testing.T, agent string, conn snmpConn) (*Runtime, *prefixPollEvidence, *captureEmitter) {
	t.Helper()
	emitter := &captureEmitter{}
	cfg := &Config{TenantID: "11111111-1111-4111-8111-111111111111", AgentID: agent, Devices: []Target{{Address: "192.0.2.1", Transport: TransportSNMPv2c, Credential: "read"}}}
	runtime, err := New(cfg, emitter, mapCreds{"read": {Community: "public"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	evidence := &prefixPollEvidence{}
	runtime.WithEntityEvidence(evidence)
	runtime.dialSNMP = stubConnDialer(conn, nil)
	return runtime, evidence, emitter
}

func TestSNMPPollPrefixEvidenceKeepsCompleteEpochAndUnavailableFence(t *testing.T) {
	const agent = "22222222-2222-4222-8222-222222222222"
	rows := []gosnmp.SnmpPDU{
		snmpPrefixPDUForTest("1", netip.MustParsePrefix("192.0.2.0/24"), 1),
		snmpPrefixPDUForTest("2", netip.MustParsePrefix("2001:db8::/64"), 2),
	}
	conn := &prefixPollConn{fakeConn: healthyConn(), prefix: &snmpPrefixSnapshotConn{rows: rows}}
	runtime, evidence, metrics := prefixPollRuntime(t, agent, conn)
	previousID := ""
	for cycle := range 4 {
		if cycle == 2 {
			conn.prefix.walkErr = errors.New("late packet failure with untrusted detail")
		} else {
			conn.prefix.walkErr = nil
		}
		before := len(evidence.claims)
		runtime.pollOnce(t.Context(), runtime.cfg.Devices[0], Credential{Community: "public"})
		claims := evidence.claims[before:]
		if len(claims) == 0 || claims[0].SourceRef != "snmp:configured-target" || claims[0].ID == previousID {
			t.Fatal("new prefix attempt retained the identity refresh epoch instead of current authority")
		}
		root := claims[0]
		previousID = root.ID
		if cycle == 2 {
			if root.SNMPInterfacePrefixes != nil {
				t.Fatal("failed latest prefix walk reused a prior or partial table")
			}
		} else if len(root.SNMPInterfacePrefixes) != 2 || root.SNMPInterfacePrefixes[0].IfIndex != 1 || root.SNMPInterfacePrefixes[1].IfIndex != 2 || root.SNMPInterfacePrefixes[1].OnLink {
			t.Fatal("current complete prefix table changed during the poll evidence path")
		}
		for _, claim := range claims {
			if claim.Source.AgentID != agent || claim.Source.SourceRef != runtime.cfg.Devices[0].Address || !claim.ObservedAt.Equal(root.ObservedAt) {
				t.Fatal("prefix poll forged source identity or split its complete collection epoch")
			}
			if claim.SourceRef != "snmp:configured-target" && claim.SNMPInterfacePrefixes != nil {
				t.Fatal("prefix metadata escaped the configured-target observation")
			}
		}
	}
	for _, batch := range evidence.batches {
		if batch[0].SourceRef == "snmp:configured-target" && len(batch) != 1 {
			t.Fatal("complete prefix table did not receive its own request envelope")
		}
	}
	stats := runtime.StatsSnapshot()
	if conn.prefix.calls != 4 || stats["interface_prefix_snapshots"] != 3 || stats["interface_prefix_unavailable"] != 1 || stats["poll_errors"] != 0 || len(metrics.snapshot()) == 0 {
		t.Fatal("prefix unavailability suppressed raw metrics or lost its observable outcome", stats)
	}
}

func TestSNMPPollPrefixEvidenceRetainsWholePopulationAndOwnsInput(t *testing.T) {
	var rows []gosnmp.SnmpPDU
	for index := 1; index <= 20000; index++ {
		rows = append(rows, snmpPrefixPDUForTest(strconv.Itoa(index), netip.MustParsePrefix("2001:db8::/32"), 1))
	}
	conn := &prefixPollConn{fakeConn: healthyConn(), prefix: &snmpPrefixSnapshotConn{rows: rows}}
	runtime, evidence, _ := prefixPollRuntime(t, "22222222-2222-4222-8222-222222222222", conn)
	runtime.pollOnce(t.Context(), runtime.cfg.Devices[0], Credential{Community: "public"})
	if len(evidence.claims) == 0 || len(evidence.claims[0].SNMPInterfacePrefixes) != len(rows) || len(evidence.batches[0]) != 1 {
		t.Fatal("complete supported in-wire prefix population was truncated during the real poll path")
	}
	captured := evidence.claims[0].SNMPInterfacePrefixes
	for i, row := range captured {
		if row.IfIndex != uint32(i+1) || row.Prefix != netip.MustParsePrefix("2001:db8::/32") || !row.OnLink {
			t.Fatal("complete prefix evidence lost exact ordered values")
		}
	}
	copy := slices.Clone(captured)
	conn.prefix.rows[0].Name, conn.prefix.rows[0].Value = "mutated after capture", 2
	if !reflect.DeepEqual(captured, copy) {
		t.Fatal("retained prefix evidence aliases transport buffers")
	}
}

func TestSNMPPollSkipsExtraPrefixFetchWithoutEvidenceChannel(t *testing.T) {
	conn := &prefixPollConn{fakeConn: healthyConn(), prefix: &snmpPrefixSnapshotConn{}}
	runtime, _, metrics := prefixPollRuntime(t, "22222222-2222-4222-8222-222222222222", conn)
	runtime.WithEntityEvidence(nil)
	runtime.pollOnce(t.Context(), runtime.cfg.Devices[0], Credential{Community: "public"})
	if conn.prefix.calls != 0 || len(metrics.snapshot()) == 0 {
		t.Fatal("raw-metric-only collector performed an unauthorized extra prefix fetch")
	}
}
