// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseSyslogLineNormalizesPriorityAndHost(t *testing.T) {
	ev := ParseSyslogLine("<134>Jul  2 12:34:56 edge-r1 %LINK-3-UPDOWN: Interface Gi0/1 down", "", time.Unix(0, 0))
	if ev.Facility != 16 || ev.Severity != 6 || ev.SeverityText != "info" {
		t.Fatalf("priority = facility %d severity %d %q", ev.Facility, ev.Severity, ev.SeverityText)
	}
	if ev.Device != "edge-r1" || !strings.Contains(ev.Message, "Interface Gi0/1 down") {
		t.Fatalf("event = %+v", ev)
	}
}

func TestMemoryOpsStoreTenantScopedSyslogAndConfig(t *testing.T) {
	st := NewMemoryOpsStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	if _, err := st.RecordSyslog(context.Background(), SyslogEvent{
		TenantID: "tenant-a", Device: "edge-a", Message: "link down", ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordSyslog(context.Background(), SyslogEvent{
		TenantID: "tenant-b", Device: "edge-b", Message: "secret event", ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListSyslog(context.Background(), "tenant-a", OpsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Device != "edge-a" {
		t.Fatalf("tenant-a syslog = %+v", got)
	}

	cfg1, err := st.ArchiveConfig(context.Background(), ConfigVersion{
		TenantID: "tenant-a", Device: "edge-a", Content: "hostname edge-a\nenable secret raw\ninterface Gi0/1\n", ObservedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg1.Content, "raw") || !strings.Contains(cfg1.Content, "[redacted]") {
		t.Fatalf("config was not redacted before storage: %q", cfg1.Content)
	}
	cfg2, err := st.ArchiveConfig(context.Background(), ConfigVersion{
		TenantID: "tenant-a", Device: "edge-a", Content: "hostname edge-a\ninterface Gi0/2\n", ObservedAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Version != 2 || !cfg2.Drifted || cfg2.PreviousHash != cfg1.ContentHash {
		t.Fatalf("drift = %+v after previous %+v", cfg2, cfg1)
	}
	if _, err := st.ArchiveConfig(context.Background(), ConfigVersion{
		TenantID: "tenant-b", Device: "edge-b", Content: "hostname secret-b", ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	configs, err := st.ListConfigs(context.Background(), "tenant-a", OpsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 {
		t.Fatalf("tenant-a configs = %+v", configs)
	}
	for _, cfg := range configs {
		if cfg.Device == "edge-b" || strings.Contains(cfg.Content, "secret-b") {
			t.Fatalf("cross-tenant config leak: %+v", configs)
		}
	}
}
