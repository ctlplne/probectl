// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/otel"
)

func (p *releaseFlowReport) provePacketFaultImpact(t *testing.T, foreign *releaseFlowReport, at time.Time, command, ca string) {
	t.Helper()
	// Keep the shipped three-minute silence threshold. This is an actual
	// stopped exporter and a live collector, not a seeded incident or clock.
	waitFor(t, "real stopped exporter mTLS fault incident", 4*time.Minute, func() bool {
		var page struct {
			Items              []incident.Incident `json:"items"`
			Truncated          bool                `json:"truncated"`
			CorrelationRunning bool                `json:"correlation_running"`
		}
		p.api.json(t, http.StatusOK, http.MethodGet, "/v1/incidents", nil, &page)
		if !page.CorrelationRunning {
			t.Fatal("release-image correlator is unavailable for real exporter fault proof")
		}
		if page.Truncated {
			t.Fatal("real fault incident search lost complete tenant population")
		}
		matches := 0
		for _, summary := range page.Items {
			if summary.TenantID != p.tenant {
				t.Fatal("incident list exposed another tenant")
			}
			if summary.Target != "127.0.0.1" {
				continue
			}
			var detail incident.Incident
			p.api.json(t, http.StatusOK, http.MethodGet, "/v1/incidents/"+summary.ID, nil, &detail)
			if detail.SignalsTruncated || detail.TenantID != p.tenant {
				t.Fatal("real exporter incident lost whole tenant evidence")
			}
			for _, signal := range detail.Signals {
				if signal.Kind == string(entity.FaultFlowExporterSilent) && signal.Attributes[otel.AttrAgentID] == p.packetAgent {
					if signal.Attributes[entity.AttrFaultObservationID] == "" || signal.Attributes[entity.AttrFaultKind] != signal.Kind || signal.Attributes[entity.AttrSourceKind] != string(entity.FlowExporter) {
						t.Fatal("real exporter fault lost its authenticated original receipt")
					}
					matches++
					p.packetIncident = detail.ID
					break
				}
			}
		}
		if matches > 1 {
			t.Fatal("one real exporter outage produced multiple tenant incidents", matches)
		}
		return matches == 1
	})
	input := incident.ImpactInput{From: at.Add(-time.Minute), To: time.Now().UTC(), CustomerTagKey: "packet_prefix_customer"}
	var impact incident.ImpactResponse
	endpoint := "/v1/incidents/" + p.packetIncident + "/impact"
	p.packetImpact = p.api.json(t, http.StatusOK, http.MethodPost, endpoint, input, &impact)
	if impact.IncidentID != p.packetIncident || impact.UnresolvedRoot || len(impact.UnresolvedSignalIDs) != 0 ||
		len(impact.Members) != 1 || impact.Members[0].ContextID != p.packetContext || impact.Members[0].EntityID != p.packetEntity || !impact.Members[0].IncidentRoot || len(impact.Members[0].SignalIDs) == 0 {
		t.Fatal("real fault impact lost its stored canonical root or original signals")
	}
	if impact.Current.UnverifiedRecords != 0 || impact.Current.AttestedRecords == 0 || impact.Current.ObservedTotals == nil || len(impact.Current.Captures) == 0 {
		t.Fatal("real fault impact did not retain original authenticated packet captures")
	}
	counts := impact.Current.ObservedTotals
	packets, err := strconv.ParseUint(counts.RawPackets, 10, 64)
	// The selected4096 requests have zero tolerance. The distinct256-packet
	// pcap flush is unrelated traffic: its last partial block may remain in
	// the kernel capture ring, so whole-device totals admit only that stated
	// range. Every retained packet still needs exact IP-byte conservation.
	if err != nil || packets < releasePacketCount || packets > releasePacketCount+256 || counts.ScaledPackets != counts.RawPackets ||
		counts.RawBytes != strconv.FormatUint(packets*(releasePacketPayload+20+8), 10) || counts.ScaledBytes != counts.RawBytes {
		t.Fatal("real fault impact disagreed with independently injected packet/IP-byte bounds", counts, err)
	}
	keys := map[string]bool{}
	for _, capture := range impact.Current.Captures {
		if capture.Key == "" || keys[capture.Key] || capture.ContextID != p.packetContext || capture.RouterID != p.packetEntity || capture.OriginalSourceID == "" || capture.CurrentSourceID == "" || capture.CapturedAt.IsZero() {
			t.Fatal("real impact capture citation lost original source ownership", capture)
		}
		keys[capture.Key] = true
	}
	if len(impact.Customers) != 1 {
		t.Fatal("real impact did not name exactly its closest-prefix customer", len(impact.Customers))
	}
	customer := impact.Customers[0]
	if customer.TagKey != input.CustomerTagKey || customer.Value != p.packetPrefixCustomer || customer.ContextID != p.packetContext ||
		len(customer.PrefixIDs) != 1 || customer.PrefixIDs[0] != p.packetPrefixEntity || customer.Current == nil ||
		customer.Current.RawPackets != strconv.Itoa(releasePacketCount) || customer.Current.ScaledPackets != customer.Current.RawPackets ||
		customer.Current.RawBytes != strconv.FormatUint(uint64(p.quantity), 10) || customer.Current.ScaledBytes != customer.Current.RawBytes || len(customer.CaptureKeys) == 0 {
		t.Fatal("real packet customer or exact selected quantities changed", customer)
	}
	for _, key := range customer.CaptureKeys {
		if !keys[key] {
			t.Fatal("customer cited a capture outside the original impact", key)
		}
	}
	if packets > releasePacketCount && impact.UnclassifiedRecords == 0 {
		t.Fatal("unrelated flush traffic was silently assigned to the selected customer")
	}
	if impact.Previous.ObservedTotals != nil || len(impact.Previous.Captures) != 0 ||
		!impact.Previous.From.Equal(input.From.Add(-7*24*time.Hour)) || !impact.Previous.To.Equal(input.To.Add(-7*24*time.Hour)) {
		t.Fatal("missing weekly packet baseline was invented or used the wrong window")
	}
	if code, _ := foreign.api.do(t, http.MethodPost, endpoint, input); code != http.StatusNotFound {
		t.Fatal("real packet incident impact crossed tenant storage", code)
	}
	p.provePacketImpactClients(t, input, command, ca, foreign)
	t.Log("real-integration: stopped softflowd -> collector silence -> mTLS original fault -> one canonical tenant incident -> authenticated packet captures and exact closest-prefix customer; selected4096 requests exact, whole-device flush allowance256 packets; weekly baseline unavailable, original G4a routing/test/SLO/native/export qualification remains separate")
}
