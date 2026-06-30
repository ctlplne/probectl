// SPDX-License-Identifier: LicenseRef-probectl-TBD

package endpoint

import (
	"testing"
	"time"
)

func TestFilterViewsCauseAndQuery(t *testing.T) {
	at := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	items := []View{
		{AgentID: "laptop-anna", LastSeenAt: at, Cause: "wifi", Slow: true,
			WiFi: &ResultView{Target: "HomeNet", Attributes: map[string]string{"wifi.band": "2.4GHz"}}},
		{AgentID: "kiosk-7", LastSeenAt: at, Cause: "isp", Slow: true,
			Summary: "ISP edge loss"},
		{AgentID: "desk-42", LastSeenAt: at, Cause: "none", Slow: false},
	}
	wifi := FilterViews(items, ListFilter{Cause: "wifi"})
	if len(wifi) != 1 || wifi[0].AgentID != "laptop-anna" {
		t.Fatalf("wifi = %+v", wifi)
	}
	impaired := FilterViews(items, ListFilter{Cause: "impaired"})
	if len(impaired) != 2 {
		t.Fatalf("impaired = %+v", impaired)
	}
	search := FilterViews(items, ListFilter{Query: "homenet"})
	if len(search) != 1 || search[0].AgentID != "laptop-anna" {
		t.Fatalf("search = %+v", search)
	}
	healthy := FilterViews(items, ListFilter{Cause: "none"})
	if len(healthy) != 1 || healthy[0].AgentID != "desk-42" {
		t.Fatalf("healthy = %+v", healthy)
	}
}

func TestListFilterRejectsUnknownCause(t *testing.T) {
	if _, err := (ListFilter{Cause: "tenant-b"}).Normalize(); err == nil {
		t.Fatal("unknown filter cause accepted")
	}
}
