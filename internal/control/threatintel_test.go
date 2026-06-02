package control

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/config"
	resultv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/result/v1"
	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/opendata"
)

func intelTestLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func loadedIOCStore() *opendata.IOCStore {
	s := opendata.NewIOCStore()
	s.Load([]opendata.IOC{
		{Type: opendata.IOCTypeIP, Value: "192.0.2.66", Source: "feodo_tracker", Category: opendata.CategoryBotnetC2, Confidence: 90, License: "abuse.ch CC0"},
		{Type: opendata.IOCTypeCIDR, Value: "198.51.100.0/24", Source: "spamhaus_drop", Category: opendata.CategorySpam, Confidence: 90},
		{Type: opendata.IOCTypeDomain, Value: "evil.example", Source: "urlhaus", Category: opendata.CategoryMalware, Confidence: 80},
		{Type: opendata.IOCTypeIP, Value: "192.0.2.5", Source: "tor_exit", Category: opendata.CategoryTorExit, Confidence: 50},
	})
	return s
}

// A peer IP on a botnet-C2 feed becomes a tenant-scoped, critical threat-plane
// signal carrying full source attribution (signal, not block — guardrail 9).
func TestIOCConsumerSignalsIPMatch(t *testing.T) {
	cs := NewIOCConsumer(nil, nil, loadedIOCStore(), nil)
	r := &resultv1.Result{TenantId: "t", CanaryType: "icmp", ServerAddress: "192.0.2.66", StartTimeUnixNano: time.Now().UnixNano()}
	sigs := cs.signals(r)
	if len(sigs) != 1 {
		t.Fatalf("want 1 signal, got %+v", sigs)
	}
	s := sigs[0]
	if s.Plane != "threat" || s.Kind != "ioc.botnet_c2" || s.TenantID != "t" || s.Target != "192.0.2.66" {
		t.Errorf("signal = %+v", s)
	}
	if s.Severity != incident.SeverityCritical {
		t.Errorf("severity = %s, want critical", s.Severity)
	}
	if s.Attributes["intel.source"] != "feodo_tracker" || s.Attributes["intel.confidence"] != "90" ||
		s.Attributes["intel.indicator"] != "192.0.2.66" || s.Attributes["intel.license"] != "abuse.ch CC0" {
		t.Errorf("provenance attrs = %+v", s.Attributes)
	}
	if s.Attributes["observed.canary_type"] != "icmp" {
		t.Errorf("missing observed canary type: %+v", s.Attributes)
	}
}

func TestIOCConsumerCIDRPortAndDomain(t *testing.T) {
	cs := NewIOCConsumer(nil, nil, loadedIOCStore(), nil)

	// IP inside a loaded CIDR, with a :port stripped before scoring
	sigs := cs.signals(&resultv1.Result{TenantId: "t", CanaryType: "tcp", ServerAddress: "198.51.100.9:443", StartTimeUnixNano: time.Now().UnixNano()})
	if len(sigs) != 1 || sigs[0].Kind != "ioc.spam" || sigs[0].Target != "198.51.100.9" || sigs[0].Attributes["intel.indicator"] != "198.51.100.0/24" {
		t.Fatalf("cidr/port match = %+v", sigs)
	}

	// hostname target scored against the domain feed
	sigs = cs.signals(&resultv1.Result{TenantId: "t", CanaryType: "http", ServerAddress: "evil.example", StartTimeUnixNano: time.Now().UnixNano()})
	if len(sigs) != 1 || sigs[0].Kind != "ioc.malware" {
		t.Fatalf("domain match = %+v", sigs)
	}

	// a Tor exit (confidence 50) is a low-severity, tunable context signal
	sigs = cs.signals(&resultv1.Result{TenantId: "t", CanaryType: "icmp", ServerAddress: "192.0.2.5", StartTimeUnixNano: time.Now().UnixNano()})
	if len(sigs) != 1 || sigs[0].Severity != incident.SeverityInfo {
		t.Fatalf("tor-exit severity = %+v", sigs)
	}
}

func TestIOCConsumerNoMatch(t *testing.T) {
	cs := NewIOCConsumer(nil, nil, loadedIOCStore(), nil)
	if s := cs.signals(&resultv1.Result{TenantId: "t", ServerAddress: "8.8.8.8"}); s != nil {
		t.Errorf("a clean IP should yield no signals: %+v", s)
	}
	if s := cs.signals(&resultv1.Result{TenantId: "t", ServerAddress: ""}); s != nil {
		t.Errorf("no address should yield no signals: %+v", s)
	}
}

func TestBuildThreatIntelGating(t *testing.T) {
	// OFF by default (no phone-home)
	if _, _, ok := BuildThreatIntel(&config.Config{ThreatIntelEnabled: false}, intelTestLog()); ok {
		t.Error("threat-intel must be OFF unless explicitly enabled")
	}
	// enabled with a known feed -> store + refresher
	store, refr, ok := BuildThreatIntel(&config.Config{ThreatIntelEnabled: true, ThreatIntelRefresh: time.Hour, ThreatIntelFeeds: []string{"feodo_tracker"}}, intelTestLog())
	if !ok || store == nil || refr == nil {
		t.Fatal("enabled threat-intel should build a store + refresher")
	}
	// enabled but no KNOWN feeds -> nothing to load -> disabled (graceful)
	if _, _, ok := BuildThreatIntel(&config.Config{ThreatIntelEnabled: true, ThreatIntelFeeds: []string{"bogus"}}, intelTestLog()); ok {
		t.Error("a feed list with no known feeds should disable threat-intel")
	}
}
