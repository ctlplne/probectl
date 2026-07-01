// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

type aupStatus struct {
	License        string `json:"license"`
	URL            string `json:"url"`
	Attribution    string `json:"attribution"`
	CommercialUse  string `json:"commercial_use"`
	Redistribution string `json:"redistribution"`
}

type openDataSourceStatus struct {
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	CadenceSeconds int64     `json:"cadence_seconds"`
	AUP            aupStatus `json:"aup"`
	Enabled        bool      `json:"enabled"`
	Status         string    `json:"status"`
	LastSuccess    string    `json:"last_success"`
	LastError      string    `json:"last_error"`
}

type threatIntelFeedStatus struct {
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	CadenceSeconds int64     `json:"cadence_seconds"`
	AUP            aupStatus `json:"aup"`
	Enabled        bool      `json:"enabled"`
	Status         string    `json:"status"`
	LastSuccess    string    `json:"last_success"`
	LastError      string    `json:"last_error"`
	IOCCount       int       `json:"ioc_count"`
}

type openDataStatusResponse struct {
	OpenDataEnabled    bool                    `json:"open_data_enabled"`
	ThreatIntelEnabled bool                    `json:"threat_intel_enabled"`
	IOCCount           int                     `json:"ioc_count"`
	OpenDataSources    []openDataSourceStatus  `json:"open_data_sources"`
	ThreatIntelFeeds   []threatIntelFeedStatus `json:"threat_intel_feeds"`
}

// WithOpenDataStatus attaches the shared open-data/threat-intel sources backing
// GET /v1/threat/intel/status. nil values are allowed: the route still returns
// the built-in threat-intel AUP matrix with enabled=false so operators can see
// what would be fetched before turning outbound feeds on.
func (s *Server) WithOpenDataStatus(en *opendata.Enricher, store *opendata.IOCStore, refresher *opendata.IntelRefresher) *Server {
	s.openDataEnricher = en
	s.iocStore = store
	s.intelRefresher = refresher
	return s
}

// handleThreatIntelStatus serves the operator's AUP + feed-health matrix. The
// payload is shared-source metadata only; there are no tenant-owned indicators,
// flows, detections, or documents in this response.
func (s *Server) handleThreatIntelStatus(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	resp := openDataStatusResponse{
		OpenDataEnabled:    s.openDataEnricher != nil,
		ThreatIntelEnabled: s.intelRefresher != nil,
		OpenDataSources:    []openDataSourceStatus{},
		ThreatIntelFeeds:   []threatIntelFeedStatus{},
	}
	if s.iocStore != nil {
		resp.IOCCount = s.iocStore.Count()
	}
	if s.openDataEnricher != nil {
		for _, st := range s.openDataEnricher.Status() {
			resp.OpenDataSources = append(resp.OpenDataSources, openDataStatusFrom(st.Descriptor, st.Health))
		}
	}
	if s.intelRefresher != nil {
		for _, st := range s.intelRefresher.Status() {
			resp.ThreatIntelFeeds = append(resp.ThreatIntelFeeds, threatIntelStatusFrom(st.Descriptor, st.Health, st.IOCCount))
		}
	} else {
		for _, desc := range builtinThreatIntelDescriptors() {
			resp.ThreatIntelFeeds = append(resp.ThreatIntelFeeds, threatIntelStatusFrom(desc, opendata.Health{Enabled: false, Status: "disabled"}, 0))
		}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func openDataStatusFrom(desc opendata.Descriptor, health opendata.Health) openDataSourceStatus {
	return openDataSourceStatus{
		Name:           desc.Name,
		Kind:           string(desc.Kind),
		CadenceSeconds: int64(desc.Cadence / time.Second),
		AUP:            aupFrom(desc.AUP),
		Enabled:        health.Enabled,
		Status:         health.Status,
		LastSuccess:    formatStatusTime(health.LastSuccess),
		LastError:      health.LastError,
	}
}

func threatIntelStatusFrom(desc opendata.Descriptor, health opendata.Health, count int) threatIntelFeedStatus {
	return threatIntelFeedStatus{
		Name:           desc.Name,
		Kind:           string(desc.Kind),
		CadenceSeconds: int64(desc.Cadence / time.Second),
		AUP:            aupFrom(desc.AUP),
		Enabled:        health.Enabled,
		Status:         health.Status,
		LastSuccess:    formatStatusTime(health.LastSuccess),
		LastError:      health.LastError,
		IOCCount:       count,
	}
}

func aupFrom(aup opendata.AUP) aupStatus {
	return aupStatus{
		License:        aup.License,
		URL:            aup.URL,
		Attribution:    aup.Attribution,
		CommercialUse:  string(aup.CommercialUse),
		Redistribution: aup.Redistribution,
	}
}

func formatStatusTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func builtinThreatIntelDescriptors() []opendata.Descriptor {
	descs := make([]opendata.Descriptor, 0, len(opendata.IntelFeedNames()))
	for _, name := range opendata.IntelFeedNames() {
		if feed, ok := opendata.NewIntelFeed(name, nil); ok {
			descs = append(descs, feed.Descriptor())
		}
	}
	return descs
}
