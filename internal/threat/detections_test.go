// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

func intelSignal(tenant, target string) incident.Signal {
	return incident.Signal{
		TenantID: tenant, Plane: "threat", Kind: "ioc.botnet",
		Severity: incident.Severity("critical"),
		Title:    target + " matches threat-intel indicator (botnet, source feodo)",
		Summary:  target + " matched 203.0.113.66 from feodo (confidence 90)",
		Target:   target,
		Attributes: map[string]string{
			"intel.source": "feodo", "intel.category": "botnet",
			"intel.type":      "ip",
			"intel.indicator": "203.0.113.66", "intel.confidence": "90",
			"intel.license": "non-commercial",
		},
		OccurredAt: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
	}
}

func TestDetectionFromSignal(t *testing.T) {
	d, ok := DetectionFromSignal(intelSignal("t-a", "203.0.113.66"), "inc-1")
	if !ok {
		t.Fatal("intel signal not recognized")
	}
	if d.Source != "feodo" || d.Confidence != 90 || d.Indicator != "203.0.113.66" ||
		d.Type != "ip" || d.Category != "botnet" || d.License != "non-commercial" ||
		d.Kind != "ioc.botnet" || d.IncidentID != "inc-1" || d.Entity != "203.0.113.66" {
		t.Fatalf("detection = %+v", d)
	}

	ndr, ok := DetectionFromSignal(incident.Signal{
		TenantID: "t-a", Plane: "threat", Kind: "ndr.beaconing",
		Severity: incident.SeverityCritical,
		Target:   "10.0.0.5",
		Title:    "Periodic beaconing",
		Attributes: map[string]string{
			"detector.rule": "ndr-beaconing-default", "detector.kind": "beaconing",
			"detector.confidence": "91",
			"intel.source":        "feodo", "intel.category": "botnet_c2",
			"intel.type": "ip", "intel.indicator": "203.0.113.66",
			"intel.license": "CC0",
		},
		OccurredAt: time.Now(),
	}, "inc-ndr")
	if !ok {
		t.Fatal("NDR intel signal not recognized")
	}
	if ndr.Source != "ndr-beaconing-default" || ndr.Category != "botnet_c2" ||
		ndr.Type != "ip" || ndr.License != "CC0" || ndr.Indicator != "203.0.113.66" ||
		ndr.Confidence != 91 {
		t.Fatalf("NDR detection provenance = %+v", ndr)
	}

	// Non-threat planes and unattributed threat signals are not detections.
	if _, ok := DetectionFromSignal(incident.Signal{Plane: "network", Target: "x"}, ""); ok {
		t.Fatal("network signal recognized as detection")
	}
	plainCert := incident.Signal{Plane: "threat", Kind: "tls.cert_expiring_soon", Target: "web:443",
		Attributes: map[string]string{"source": "http"}}
	if _, ok := DetectionFromSignal(plainCert, ""); ok {
		t.Fatal("unattributed cert-expiry signal recognized as detection (would flood triage)")
	}
}

func TestDetectionStoreTenantScopingAndCap(t *testing.T) {
	s := NewDetectionStore(3)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.Record("t-a", Detection{Entity: fmt.Sprintf("10.0.0.%d", i), Severity: "warning",
			ObservedAt: at.Add(time.Duration(i) * time.Minute)})
	}
	s.Record("t-b", Detection{Entity: "secret.other", Severity: "critical", ObservedAt: at})
	s.Record("", Detection{Entity: "ghost"}) // unscoped: dropped
	s.Record("t-a", Detection{Entity: ""})   // entity-less: dropped
	if s.Len("t-a") != 3 || s.Len("t-b") != 1 || s.Len("") != 0 {
		t.Fatalf("partitions: a=%d b=%d empty=%d", s.Len("t-a"), s.Len("t-b"), s.Len(""))
	}

	got := s.List("t-a")
	// Newest first; oldest evicted by the cap.
	if got[0].Entity != "10.0.0.4" || got[2].Entity != "10.0.0.2" {
		t.Fatalf("order = %v %v %v", got[0].Entity, got[1].Entity, got[2].Entity)
	}
	for _, d := range got {
		if d.Entity == "secret.other" {
			t.Fatal("CROSS-TENANT LEAK in List")
		}
		if d.ID == "" {
			t.Fatal("detection without ID")
		}
	}
}
