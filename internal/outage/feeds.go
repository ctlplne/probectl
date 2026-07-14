// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package outage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

// KindOutage classifies outage feeds in the shared open-data provenance model.
const KindOutage opendata.Kind = "outage"

// Feed is one public outage-signal source (the open-data side of the
// collective view). Fetch returns events starting after since; a failure
// returns an error and the refresher keeps the source's last-good events
// (graceful degradation — guardrail 10).
type Feed interface {
	Descriptor() opendata.Descriptor
	Fetch(ctx context.Context, since time.Time) ([]Event, error)
}

// Public outage-feed endpoints. Fetched over hardened TLS (certificate
// validation on — guardrail 12); bodies are untrusted input, decoded
// defensively with a size cap.
const (
	urlIODA  = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events"
	urlRadar = "https://api.cloudflare.com/client/v4/radar/annotations/outages"

	maxFeedBody = 8 << 20 // generous for both feeds' JSON
)

func defaultClient() opendata.Doer { return crypto.HardenedHTTPClient(20 * time.Second) }

// FeedNames lists the built-in outage feeds.
func FeedNames() []string { return []string{"ioda", "cloudflare_radar"} }

// NewFeeds builds the named feeds (empty names = all built-ins). The
// Cloudflare Radar API requires a token; without one the radar feed is
// omitted (the caller logs it — degraded honestly, not silently). client nil
// = the hardened-TLS default.
func NewFeeds(names []string, radarToken string, client opendata.Doer) []Feed {
	if len(names) == 0 {
		names = FeedNames()
	}
	var out []Feed
	for _, n := range names {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "ioda":
			out = append(out, NewIODA(client))
		case "cloudflare_radar", "cloudflare-radar", "radar":
			if radarToken != "" {
				out = append(out, NewRadar(radarToken, client))
			}
		}
	}
	return out
}

// --- IODA (Internet Outage Detection and Analysis, Georgia Tech) ---

// ioda adapts the IODA v2 outage-events API. Events carry an entity (asn /
// country / region), a start + duration, and a per-datasource score.
type ioda struct {
	client opendata.Doer
	base   string
}

// NewIODA builds the IODA feed adapter.
func NewIODA(client opendata.Doer) Feed {
	if client == nil {
		client = defaultClient()
	}
	return &ioda{client: client, base: urlIODA}
}

func (f *ioda) Descriptor() opendata.Descriptor {
	return opendata.Descriptor{
		Name: "ioda", Kind: KindOutage, Cadence: 10 * time.Minute,
		AUP: opendata.AUP{
			License:       "IODA data-usage terms (academic project; attribution requested)",
			URL:           "https://ioda.inetintel.cc.gatech.edu/",
			Attribution:   "IODA, Georgia Institute of Technology",
			CommercialUse: opendata.CommercialUnknown,
		},
	}
}

// iodaEvent mirrors the v2 API event shape, decoded defensively: both the
// entity object and the flat location fields are accepted.
type iodaEvent struct {
	Entity struct {
		Type string `json:"type"`
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"entity"`
	Location     string  `json:"location"`
	LocationName string  `json:"location_name"`
	Start        int64   `json:"start"`    // unix seconds
	Duration     int64   `json:"duration"` // seconds; 0 = ongoing
	Score        float64 `json:"score"`
	Datasource   string  `json:"datasource"`
}

func (f *ioda) Fetch(ctx context.Context, since time.Time) ([]Event, error) {
	q := url.Values{}
	q.Set("from", strconv.FormatInt(since.Unix(), 10))
	q.Set("until", strconv.FormatInt(time.Now().Unix(), 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outage ioda: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("outage ioda: status %d", resp.StatusCode)
	}
	var body struct {
		Data []iodaEvent `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFeedBody)).Decode(&body); err != nil {
		return nil, fmt.Errorf("outage ioda: decode: %w", err)
	}
	var out []Event
	for _, ev := range body.Data {
		e, ok := f.normalize(ev)
		if !ok {
			continue // malformed item — skip, never fail the batch
		}
		out = append(out, e)
	}
	return out, nil
}

func (f *ioda) normalize(ev iodaEvent) (Event, bool) {
	typ, code, name := ev.Entity.Type, ev.Entity.Code, ev.Entity.Name
	if code == "" {
		code, name = ev.Location, ev.LocationName
	}
	scope, ok := iodaScope(typ, code, name)
	if !ok || ev.Start <= 0 {
		return Event{}, false
	}
	start := time.Unix(ev.Start, 0).UTC()
	var end time.Time
	if ev.Duration > 0 {
		end = start.Add(time.Duration(ev.Duration) * time.Second)
	}
	title := fmt.Sprintf("Internet outage: %s", scopeLabel(scope))
	summary := fmt.Sprintf("IODA %s signal, score %.0f", ev.Datasource, ev.Score)
	return Event{
		ID:         fmt.Sprintf("ioda:%s:%s:%d", ev.Datasource, scope.Key(), ev.Start),
		Source:     "ioda",
		Scope:      scope,
		Severity:   iodaSeverity(ev.Score),
		Confidence: minF(1, ev.Score/iodaScoreSaturation),
		Title:      title,
		Summary:    summary,
		Start:      start,
		End:        end,
		Evidence:   iodaLink(scope),
	}, true
}

// iodaScoreSaturation maps IODA's open-ended scores onto 0..1 confidence —
// a documented heuristic, not a vendor-calibrated probability.
const iodaScoreSaturation = 200.0

func iodaSeverity(score float64) string {
	switch {
	case score >= 500:
		return "critical"
	case score >= 50:
		return "warning"
	default:
		return "info"
	}
}

func iodaScope(typ, code, name string) (Scope, bool) {
	if code == "" {
		return Scope{}, false
	}
	switch strings.ToLower(typ) {
	case "asn":
		return Scope{Kind: ScopeASN, Code: asCode(code), Name: name}, true
	case "country":
		return Scope{Kind: ScopeCountry, Code: strings.ToUpper(code), Name: name}, true
	case "region", "county", "continent":
		return Scope{Kind: ScopeRegion, Code: code, Name: name}, true
	case "":
		// Flat location field: "AS174" or a country code.
		if strings.HasPrefix(strings.ToUpper(code), "AS") {
			return Scope{Kind: ScopeASN, Code: strings.ToUpper(code), Name: name}, true
		}
		if len(code) == 2 {
			return Scope{Kind: ScopeCountry, Code: strings.ToUpper(code), Name: name}, true
		}
		return Scope{Kind: ScopeUnknown, Code: code, Name: name}, true
	default:
		return Scope{Kind: ScopeUnknown, Code: code, Name: name}, true
	}
}

func iodaLink(s Scope) string {
	switch s.Kind {
	case ScopeASN:
		return "https://ioda.inetintel.cc.gatech.edu/asn/" + strings.TrimPrefix(s.Code, "AS")
	case ScopeCountry:
		return "https://ioda.inetintel.cc.gatech.edu/country/" + s.Code
	default:
		return "https://ioda.inetintel.cc.gatech.edu/"
	}
}

// --- Cloudflare Radar outage annotations ---

// radar adapts the Cloudflare Radar outage-annotations API (token required).
type radar struct {
	client opendata.Doer
	base   string
	token  string
}

// NewRadar builds the Radar feed adapter.
func NewRadar(token string, client opendata.Doer) Feed {
	if client == nil {
		client = defaultClient()
	}
	return &radar{client: client, base: urlRadar, token: token}
}

func (f *radar) Descriptor() opendata.Descriptor {
	return opendata.Descriptor{
		Name: "cloudflare_radar", Kind: KindOutage, Cadence: 10 * time.Minute,
		AUP: opendata.AUP{
			License:       "CC BY-NC 4.0 (non-commercial)",
			URL:           "https://radar.cloudflare.com/about",
			Attribution:   "Cloudflare Radar",
			CommercialUse: opendata.CommercialRestricted,
		},
	}
}

// radarAnnotation mirrors the Radar outage-annotation shape (decoded
// defensively; unknown fields ignored).
type radarAnnotation struct {
	ID               string   `json:"id"`
	DataSource       string   `json:"dataSource"`
	Description      string   `json:"description"`
	StartDate        string   `json:"startDate"`
	EndDate          string   `json:"endDate"`
	Locations        []string `json:"locations"`
	LocationsDetails []struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"locationsDetails"`
	ASNs        []json.Number `json:"asns"`
	ASNsDetails []struct {
		ASN  string `json:"asn"`
		Name string `json:"name"`
	} `json:"asnsDetails"`
	Outage struct {
		OutageCause string `json:"outageCause"`
		OutageType  string `json:"outageType"`
	} `json:"outage"`
}

func (f *radar) Fetch(ctx context.Context, since time.Time) ([]Event, error) {
	q := url.Values{}
	q.Set("dateRange", radarRange(time.Since(since)))
	q.Set("limit", "100")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outage radar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("outage radar: status %d", resp.StatusCode)
	}
	var body struct {
		Success bool `json:"success"`
		Result  struct {
			Annotations []radarAnnotation `json:"annotations"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFeedBody)).Decode(&body); err != nil {
		return nil, fmt.Errorf("outage radar: decode: %w", err)
	}
	if !body.Success {
		return nil, fmt.Errorf("outage radar: api reported failure")
	}
	var out []Event
	for _, a := range body.Result.Annotations {
		out = append(out, f.normalize(a)...)
	}
	return out, nil
}

// maxScopesPerAnnotation caps the per-scope expansion of one annotation.
const maxScopesPerAnnotation = 8

// normalize expands one annotation into per-scope events (an annotation may
// name several ASNs + countries; correlation joins on scope).
func (f *radar) normalize(a radarAnnotation) []Event {
	if a.ID == "" {
		return nil
	}
	start, err := time.Parse(time.RFC3339, a.StartDate)
	if err != nil {
		return nil
	}
	var end time.Time
	if a.EndDate != "" {
		if t, err := time.Parse(time.RFC3339, a.EndDate); err == nil {
			end = t
		}
	}
	scopes := radarScopes(a)
	if len(scopes) == 0 {
		return nil
	}
	sev := "warning"
	if strings.EqualFold(a.Outage.OutageType, "NATIONWIDE") {
		sev = "critical"
	}
	summary := a.Description
	if a.Outage.OutageCause != "" {
		summary = strings.TrimSpace(summary + " (cause: " + strings.ToLower(a.Outage.OutageCause) + ")")
	}
	var out []Event
	for _, s := range scopes {
		out = append(out, Event{
			ID:         "cloudflare_radar:" + a.ID + ":" + s.Key(),
			Source:     "cloudflare_radar",
			Scope:      s,
			Severity:   sev,
			Confidence: 0.9, // Radar annotations are curated — documented heuristic
			Title:      fmt.Sprintf("Internet outage: %s", scopeLabel(s)),
			Summary:    summary,
			Start:      start.UTC(),
			End:        end,
			Evidence:   "https://radar.cloudflare.com/outage-center",
		})
	}
	return out
}

func radarScopes(a radarAnnotation) []Scope {
	var out []Scope
	add := func(s Scope) {
		if len(out) < maxScopesPerAnnotation {
			out = append(out, s)
		}
	}
	asnName := map[string]string{}
	for _, d := range a.ASNsDetails {
		asnName[d.ASN] = d.Name
	}
	for _, n := range a.ASNs {
		code := n.String()
		add(Scope{Kind: ScopeASN, Code: asCode(code), Name: asnName[code]})
	}
	locName := map[string]string{}
	for _, d := range a.LocationsDetails {
		locName[d.Code] = d.Name
	}
	for _, l := range a.Locations {
		add(Scope{Kind: ScopeCountry, Code: strings.ToUpper(l), Name: locName[l]})
	}
	return out
}

// radarRange maps the retention lookback onto Radar's dateRange parameter.
func radarRange(d time.Duration) string {
	switch {
	case d <= 24*time.Hour:
		return "1d"
	case d <= 48*time.Hour:
		return "2d"
	case d <= 7*24*time.Hour:
		return "7d"
	default:
		return "14d"
	}
}

// --- shared helpers ---

func asCode(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if !strings.HasPrefix(c, "AS") {
		c = "AS" + c
	}
	return c
}

func scopeLabel(s Scope) string {
	if s.Name != "" {
		return fmt.Sprintf("%s (%s)", s.Name, s.Code)
	}
	return s.Code
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
