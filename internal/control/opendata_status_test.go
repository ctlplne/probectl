// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

func statusQuietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeOpenDataSource struct {
	desc opendata.Descriptor
	err  error
}

func (s fakeOpenDataSource) Descriptor() opendata.Descriptor { return s.desc }

func (s fakeOpenDataSource) Enrich(context.Context, netip.Addr, *opendata.Enrichment) error {
	return s.err
}

type fakeIntelFeed struct {
	desc opendata.Descriptor
	iocs []opendata.IOC
	err  error
}

func (f fakeIntelFeed) Descriptor() opendata.Descriptor { return f.desc }

func (f fakeIntelFeed) Fetch(context.Context) ([]opendata.IOC, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.iocs, nil
}

func TestOpenDataStatusRoute(t *testing.T) {
	en := opendata.NewEnricher(statusQuietLog())
	en.Register(fakeOpenDataSource{desc: opendata.Descriptor{
		Name:    "test_cymru",
		Kind:    opendata.KindASN,
		Cadence: 24 * time.Hour,
		AUP: opendata.AUP{
			License:        "test license",
			URL:            "https://terms.example/opendata",
			Attribution:    "Example Data",
			CommercialUse:  opendata.CommercialAttribution,
			Redistribution: "cached lookup only",
		},
	}})
	if _, err := en.Enrich(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("seed opendata health: %v", err)
	}

	store := opendata.NewIOCStore()
	refresher := opendata.NewIntelRefresher(store, []opendata.ThreatIntelSource{
		fakeIntelFeed{
			desc: opendata.Descriptor{
				Name:    "feodo_tracker",
				Kind:    opendata.KindThreatIntel,
				Cadence: time.Hour,
				AUP: opendata.AUP{
					License:       "abuse.ch CC0",
					URL:           "https://abuse.ch/",
					CommercialUse: opendata.CommercialAllowed,
				},
			},
			iocs: []opendata.IOC{{
				Type:       opendata.IOCTypeIP,
				Value:      "203.0.113.66",
				Source:     "feodo_tracker",
				Category:   opendata.CategoryBotnetC2,
				Confidence: 90,
				License:    "abuse.ch CC0",
			}},
		},
		fakeIntelFeed{
			desc: opendata.Descriptor{
				Name:    "sslbl",
				Kind:    opendata.KindThreatIntel,
				Cadence: time.Hour,
				AUP: opendata.AUP{
					License:       "abuse.ch CC0",
					URL:           "https://sslbl.abuse.ch/",
					CommercialUse: opendata.CommercialAllowed,
				},
			},
			err: errors.New("feed unavailable"),
		},
	}, time.Hour, statusQuietLog())
	if got := refresher.Refresh(context.Background()); got != 1 {
		t.Fatalf("Refresh loaded %d IOCs, want 1", got)
	}

	srv := testServer(fakePinger{}).WithOpenDataStatus(en, store, refresher)
	rec := do(srv, http.MethodGet, "/v1/threat/intel/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp openDataStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OpenDataEnabled || !resp.ThreatIntelEnabled || resp.IOCCount != 1 {
		t.Fatalf("top-level status = %+v", resp)
	}
	if len(resp.OpenDataSources) != 1 {
		t.Fatalf("open_data_sources = %+v", resp.OpenDataSources)
	}
	ods := resp.OpenDataSources[0]
	if ods.Name != "test_cymru" || ods.Kind != "asn" || !ods.Enabled || ods.Status != "ok" || ods.LastSuccess == "" {
		t.Fatalf("opendata status = %+v", ods)
	}
	if ods.AUP.License != "test license" || ods.AUP.CommercialUse != string(opendata.CommercialAttribution) {
		t.Fatalf("opendata AUP = %+v", ods.AUP)
	}
	if len(resp.ThreatIntelFeeds) != 2 {
		t.Fatalf("threat_intel_feeds = %+v", resp.ThreatIntelFeeds)
	}
	if resp.ThreatIntelFeeds[0].Name != "feodo_tracker" || resp.ThreatIntelFeeds[0].IOCCount != 1 ||
		resp.ThreatIntelFeeds[0].LastSuccess == "" || resp.ThreatIntelFeeds[0].AUP.License != "abuse.ch CC0" {
		t.Fatalf("good feed status = %+v", resp.ThreatIntelFeeds[0])
	}
	if resp.ThreatIntelFeeds[1].Name != "sslbl" || resp.ThreatIntelFeeds[1].Status != "failed" ||
		resp.ThreatIntelFeeds[1].LastError != "feed unavailable" || resp.ThreatIntelFeeds[1].IOCCount != 0 {
		t.Fatalf("failed feed status = %+v", resp.ThreatIntelFeeds[1])
	}

	bare := do(testServer(fakePinger{}), http.MethodGet, "/v1/threat/intel/status")
	if bare.Code != http.StatusOK {
		t.Fatalf("bare status = %d body=%s", bare.Code, bare.Body.String())
	}
	var disabled openDataStatusResponse
	if err := json.Unmarshal(bare.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if disabled.OpenDataEnabled || disabled.ThreatIntelEnabled || disabled.IOCCount != 0 {
		t.Fatalf("disabled top-level status = %+v", disabled)
	}
	if len(disabled.ThreatIntelFeeds) != len(opendata.IntelFeedNames()) {
		t.Fatalf("disabled feed matrix has %d feeds, want %d", len(disabled.ThreatIntelFeeds), len(opendata.IntelFeedNames()))
	}
	for _, feed := range disabled.ThreatIntelFeeds {
		if feed.Enabled || feed.Status != "disabled" || feed.AUP.License == "" {
			t.Fatalf("disabled feed should preserve AUP with disabled health: %+v", feed)
		}
	}
}

func TestOpenDataStatusPerm(t *testing.T) {
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		if rt.Pattern == "/v1/threat/intel/status" {
			if rt.Permission != permThreatRead {
				t.Fatalf("perm = %q, want threat.read", rt.Permission)
			}
			return
		}
	}
	t.Fatal("/v1/threat/intel/status not registered")
}
