// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// These are the publisher's documented file/scope pairs; all addresses below
// are QA-authored. They are not network probes or actual Zoom traffic.
var zoomGoldenDocuments = []struct {
	id, file, service string
	ipv6, dependency  bool
}{
	{"zoom_common", "Zoom.txt", "Zoom", false, false},
	{"zoom_meetings_ipv4", "ZoomMeetings.txt", "Zoom Meetings", false, false},
	{"zoom_meetings_ipv6", "ZoomMeetings-IPv6.txt", "Zoom Meetings", true, false},
	{"zoom_crc", "ZoomCRC.txt", "Zoom Cloud Room Connector", false, false},
	{"zoom_phone_ipv4", "ZoomPhone.txt", "Zoom Phone", false, false},
	{"zoom_phone_ipv6", "ZoomPhone-IPv6.txt", "Zoom Phone", true, false},
	{"zoom_phone_tcp443", "ZoomPhone-TCP443.txt", "Zoom Phone", false, false},
	{"zoom_phone_tcp5091", "ZoomPhone-TCP5091.txt", "Zoom Phone", false, false},
	{"zoom_phone_tcp390", "ZoomPhone-TCP390.txt", "Zoom Phone", false, false},
	{"zoom_phone_udp3478", "ZoomPhone-UDP3478.txt", "Zoom Phone", false, false},
	{"zoom_phone_udp20000_64000", "ZoomPhone-UDP20000-64000.txt", "Zoom Phone", false, false},
	{"zoom_contact_center_ipv4", "ZoomCC.txt", "Zoom Contact Center", false, false},
	{"zoom_contact_center_ipv6", "ZoomCC-IPv6.txt", "Zoom Contact Center", true, false},
	{"zoom_contact_center_widget", "ZCCFlowScriptCallWidget.txt", "Zoom Contact Center widget network dependency", false, true},
	{"zoom_virtual_agent_ipv4", "ZoomZVA.txt", "Zoom Virtual Agent", false, false},
	{"zoom_virtual_agent_ipv6", "ZoomZVA-IPv6.txt", "Zoom Virtual Agent", true, false},
	{"zoom_virtual_agent_widget", "ZVAFlowScriptCallWidget.txt", "Zoom Virtual Agent widget network dependency", false, true},
	{"zoom_cdn_ipv4", "ZoomCDN.txt", "Zoom CDN network dependency", false, true},
	{"zoom_cdn_ipv6", "ZoomCDN-IPv6.txt", "Zoom CDN network dependency", true, true},
	{"zoom_apps", "ZoomApps.txt", "Zoom Apps network dependency", false, true},
	{"zoom_apps_ipv6", "ZoomApps-IPv6.txt", "Zoom Apps network dependency", true, true},
	{"zoom_pso_ipv4", "ZoomPSO.txt", "Zoom PSO Network Assessment", false, false},
}

func TestZoomPublishedBulkKeepsEveryProductFamilyOriginalTextAndUnknownDependencies(t *testing.T) {
	bodies := map[string]string{}
	for index, document := range zoomGoldenDocuments {
		prefix := fmt.Sprintf("198.18.%d.0/24", index)
		if document.ipv6 {
			prefix = fmt.Sprintf("2001:db8:%x::/48", index)
		}
		if document.id == "zoom_common" || document.id == "zoom_meetings_ipv4" {
			prefix = "192.0.2.0/24"
		}
		if document.id == "zoom_virtual_agent_ipv6" {
			prefix = "2001:db8:64::7"
		}
		if document.id == "zoom_phone_tcp443" {
			prefix = "198.51.100.33"
		}
		bodies[document.file] = "\r\n" + prefix + "\r\n\n"
	}
	requests := 0
	bad := ""
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "assets.zoom.us" || req.URL.RawQuery != "" || req.Header.Get("Authorization") != "" || req.Header.Get("X-Probectl-Tenant") != "" || len(req.Cookies()) != 0 {
			t.Fatal("Zoom bulk request escaped its public source or carried telemetry")
		}
		name := strings.TrimPrefix(req.URL.Path, "/docs/ipranges/")
		body, ok := bodies[name]
		if !ok {
			t.Fatal("Zoom bundle omitted its documented source inventory", name)
		}
		requests++
		if name == "ZoomMeetings-IPv6.txt" {
			switch bad {
			case "wrong family":
				body = "192.0.2.0/24\n"
			case "invalid UTF-8":
				body = "2001:db8::/32\n\xff"
			case "incomplete publisher response":
				body = "<html>source unavailable</html>"
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	path := filepath.Join(t.TempDir(), "complete.json")
	if err := FetchServiceRangeCache(t.Context(), path, []string{"zoom"}, time.Hour, 16<<20, client); err != nil {
		t.Fatal("complete Zoom product/family bundle refused", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope serviceRangeEnvelope
	if err := json.Unmarshal(original, &envelope); err != nil || len(envelope.Sources) != len(zoomGoldenDocuments) || requests != len(zoomGoldenDocuments) {
		t.Fatal("bundle did not fetch every original document once", requests, err)
	}
	at := time.Now().UTC()
	source, err := LoadServiceRanges(t.Context(), path, time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range zoomGoldenDocuments {
		var captured *serviceRangeInput
		for index := range envelope.Sources {
			if envelope.Sources[index].Publisher == document.id {
				captured = &envelope.Sources[index]
			}
		}
		body := bodies[document.file]
		if captured == nil || !bytes.Equal(captured.Data, []byte(body)) {
			t.Fatal("bundle lost original scope, family, whitespace or bytes", document.id)
		}
		value := strings.TrimSpace(body)
		var address netip.Addr
		if strings.Contains(value, "/") {
			address = netip.MustParsePrefix(value).Addr()
		} else {
			address = netip.MustParseAddr(value)
		}
		var match ServiceRangeStatus
		for _, status := range source.lookup(address, at, true) {
			if status.Publisher == document.id {
				match = status
			}
		}
		if match.Status != "matched" || match.Digest != hex.EncodeToString(crypto.Hash([]byte(body))) || !match.PublishedAt.IsZero() || len(match.Matches) != 1 || match.Matches[0].Service != document.service || match.Matches[0].Region != "" {
			t.Fatal("source scope/original digest changed or an unknown region/clock was invented", document.id, match)
		}
		if document.id == "zoom_virtual_agent_ipv6" && match.Matches[0].Prefix != "2001:db8:64::7/128" || document.id == "zoom_phone_tcp443" && match.Matches[0].Prefix != "198.51.100.33/32" {
			t.Fatal("bare publisher address changed its exact host scope", document.id, match)
		}
		classification := ClassifyServiceRanges([]ServiceRangeStatus{match}, at)
		if document.dependency {
			if classification.Status != "unknown" || classification.Service != "" || len(classification.Sources[0].Matches) != 1 {
				t.Fatal("shared network dependency became an application identity or lost provenance", document.id, classification)
			}
		} else if classification.Status != "known" || classification.Provider != "zoom" || classification.Service != document.service {
			t.Fatal("Zoom product/family attribution changed", document.id, classification)
		}
	}
	all := source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)
	if match := ClassifyServiceRanges(all, at); match.Service != "Zoom Meetings" || match.Region != "" {
		t.Fatal("generic superset hid specific Zoom attribution", match)
	}
	cloud := ServiceRangeStatus{Publisher: "aws", Status: "matched", FetchedAt: at.Add(-time.Minute), ValidUntil: at.Add(time.Hour), Matches: []ServiceRangeMatch{{Prefix: "192.0.2.0/25", Service: "EC2", Region: "us-east-1"}, {Prefix: "192.0.2.0/25", Service: "AMAZON", Region: "us-east-1"}}}
	if match := ClassifyServiceRanges(append(all, cloud), at); match.Service != "Zoom Meetings" || match.Provider != "zoom" {
		t.Fatal("hosting infrastructure hid the more specific product list", match)
	}
	cloud.Matches = []ServiceRangeMatch{{Prefix: "192.0.2.0/24", Service: "S3", Region: "us-east-1"}}
	if match := ClassifyServiceRanges(append(all, cloud), at); match.Status != "ambiguous" || match.Service != "" {
		t.Fatal("conflicting service lists were reduced to an arbitrary winner", match)
	}
	for _, status := range source.lookup(netip.MustParseAddr("192.0.2.7"), at.Add(2*time.Hour), true) {
		if status.Status != "stale" || len(status.Matches) != 0 {
			t.Fatal("stale text source retained an attribution", status)
		}
	}
	for _, mode := range []string{"wrong family", "invalid UTF-8", "incomplete publisher response"} {
		bad = mode
		if err := FetchServiceRangeCache(t.Context(), path, []string{"zoom"}, time.Hour, 16<<20, client); err == nil {
			t.Fatal("untrusted source partially replaced the bundle", mode)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, original) {
			t.Fatal("bad source changed original cache bytes/clocks", mode, err)
		}
	}
}
