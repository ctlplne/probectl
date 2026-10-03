// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// RTP-14: a fully air-gapped stack loads threat-intel feeds from a local
// file:// mirror (an IOC match raises a detection) and enriches ASNs from a
// local file — with NO outbound internet call. Driven through the real build
// seams (BuildThreatIntel, BuildEnrichment) and the real IOC-match path.
func TestAirGappedThreatIntelAndASNFromLocalMirror(t *testing.T) {
	dir := t.TempDir()

	// Threat-intel mirror: operator drops each feed under its source name.
	const iocIP = "192.0.2.66"
	if err := os.WriteFile(filepath.Join(dir, "feodo_tracker"), []byte("# air-gap mirror\n"+iocIP+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ASN local file (MaxMind GeoLite2-ASN CSV shape).
	asnPath := filepath.Join(dir, "GeoLite2-ASN-Blocks-IPv4.csv")
	if err := os.WriteFile(asnPath, []byte("network,autonomous_system_number,autonomous_system_organization\n192.0.2.0/24,64500,\"EXAMPLE-NET\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ThreatIntelEnabled: true,
		ThreatIntelRefresh: time.Hour,
		ThreatIntelFeeds:   []string{"feodo_tracker"},
		ThreatIntelMirror:  "file://" + dir,
		FlowEnrichASN:      true, // also set — must be SUPERSEDED by the file (no DNS)
		FlowEnrichASNFile:  asnPath,
		FlowEnrichCacheMax: 16,
	}

	// --- feed load from the file mirror + IOC match → detection (no network) ---
	store, refresher, ok := BuildThreatIntel(cfg, intelTestLog())
	if !ok || store == nil || refresher == nil {
		t.Fatal("air-gapped threat-intel with a mirror should build a store + refresher")
	}
	if n := refresher.Refresh(context.Background()); n != 1 {
		t.Fatalf("loaded %d IOCs from the file mirror, want 1", n)
	}
	cs := NewIOCConsumer(nil, nil, store, nil)
	sigs := cs.signals(&resultv1.Result{
		TenantId: "t", CanaryType: "icmp", ServerAddress: iocIP,
		StartTimeUnixNano: time.Now().UnixNano(),
	})
	if len(sigs) != 1 || sigs[0].Kind != "ioc.botnet_c2" || sigs[0].Attributes["intel.source"] != "feodo_tracker" {
		t.Fatalf("mirrored IOC did not raise a detection: %+v", sigs)
	}

	// --- ASN enrichment from the local file, with NO Team Cymru DNS source ---
	en, ok := BuildEnrichment(cfg, intelTestLog())
	if !ok {
		t.Fatal("ASN-file enrichment should build")
	}
	for _, st := range en.Status() {
		if st.Descriptor.Name == "team-cymru" {
			t.Fatal("Team Cymru DNS source registered despite a local ASN file (air-gap violated)")
		}
	}
	e, err := en.Enrich(context.Background(), "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if e.ASN != 64500 || e.ASName != "EXAMPLE-NET" {
		t.Fatalf("ASN enrichment from the local file = %+v, want ASN 64500 EXAMPLE-NET", e)
	}
}
