// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/threat"
)

type observedTLSLane struct {
	id, cookie, token, agent string
	target, serial, subject  string
	issuer                   string
	expiry                   time.Time
	shouldWarn               bool
}

type observedTLSInventory struct {
	Running bool             `json:"collector_running"`
	Items   []threat.Posture `json:"items"`
}

func TestShippedHTTPSCanariesExposeOnlyOwnedCertificatePosture(t *testing.T) {
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	dir := t.TempDir()
	t.Setenv("PROBECTL_AGENT_CANARY_CA_DIR", dir)
	lanes := [2]observedTLSLane{}
	var roots [2]string
	var hash string
	for i := range lanes {
		lane := &lanes[i]
		ttl := 72 * time.Hour
		lane.shouldWarn = i == 0
		if lane.shouldWarn {
			ttl = 8 * time.Hour
		}
		target, caFile := startPostureTarget(t, dir, fmt.Sprintf("endpoint-%s-%d", stamp, i), ttl)
		roots[i] = caFile
		leaf := target.Certificate()
		lane.target, lane.serial = target.URL+"/health", leaf.SerialNumber.String()
		lane.subject, lane.issuer, lane.expiry = leaf.Subject.String(), leaf.Issuer.String(), leaf.NotAfter
		if i == 0 {
			hash = crypto.CertSHA1(leaf)
		}
	}
	mirror := t.TempDir()
	feedPath := filepath.Join(mirror, "sslbl")
	row := fmt.Sprintf("%s,%s,probectl controlled certificate marker\n", time.Now().UTC().Format(time.DateTime), hash)
	if err := os.WriteFile(feedPath, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	stack := shipped.Start(t, shipped.Options{Name: "tlsposture", TenantBand: 3, Env: map[string]string{
		"PROBECTL_TLS_EXPIRY_WARNING":  "24h",
		"PROBECTL_THREATINTEL_ENABLED": "true",
		"PROBECTL_THREATINTEL_FEEDS":   "sslbl",
		"PROBECTL_THREATINTEL_REFRESH": "5s",
		"PROBECTL_THREATINTEL_MIRROR":  mirror,
	}})
	operator := stack.OnboardOperator(t, "root@msp-tls-posture.example")
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		slug := fmt.Sprintf("posture-%s-%d", stamp, i)
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		lane.id = tenant.ID
		lane.cookie = stack.SignIn(t, lane.id, email, slug)
		lane.token = stack.APIToken(t, lane.cookie, "threat.read")
		var err error
		lane.agent, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		caFile := roots[i]
		code, raw := stack.Do(t, lane.cookie, http.MethodPost, "/v1/tests", map[string]any{
			"name": slug, "type": "http", "target": lane.target, "interval_seconds": 10, "timeout_seconds": 5, "enabled": true,
			"params": map[string]string{"allow_private_targets": "true", "ca_file": caFile},
		})
		var test struct{ ID string }
		if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
			t.Fatalf("tenant %s could not create the HTTPS test (status %d)", lane.id, code)
		}
		identity := stack.EnrollAgent(t, lane.id, lane.agent, slug)
		stack.StartAgent(t, identity, slug, []string{"http"}, fmt.Sprintf(`canaries:
  - test_id: %q
    type: http
    target: %q
    interval: 10s
    timeout: 5s
    params:
      allow_private_targets: "true"
      ca_file: %q
`, test.ID, lane.target, caFile))
	}
	for _, lane := range lanes {
		shipped.Await(t, lane.target+" certificate posture", 70*time.Second, func() bool {
			return len(readTLSInventory(t, stack, lane.cookie).Items) != 0
		})
	}
	proveShippedTLSIntel(t, stack, lanes, feedPath, hash)
	for i, lane := range lanes {
		sibling := lanes[1-i]
		got := readTLSInventory(t, stack, lane.cookie)
		checkTLSInventory(t, lane, got)
		var cli observedTLSInventory
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.token}, &cli, "tls", "posture")
		checkTLSInventory(t, lane, cli)
		expect := []string{"Certificate inventory", lane.target, "Threat-intel feed status", "SSLBL CC0 1.0", "1 IOCs", "degraded"}
		absent := []string{sibling.target}
		if lane.shouldWarn {
			expect = append(expect, hash)
		} else {
			absent = append(absent, hash)
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/security", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
			Theme: []string{"light", "dark"}[i], Accessibility: true,
			Expect: expect, Absent: absent,
		})
	}
	provePublishedSSLBLArchive(t, stack, lanes, feedPath)
}

func startPostureTarget(t *testing.T, dir, name string, ttl time.Duration) (*httptest.Server, string) {
	t.Helper()
	ca, err := crypto.GenerateCA(name+" CA", 96*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificate, key, err := ca.IssueServerCert(name, []string{"127.0.0.1"}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, name+".ca.pem")
	certFile := filepath.Join(dir, name+".pem")
	keyFile := filepath.Join(dir, name+".key")
	for file, data := range map[string][]byte{caFile: ca.CertPEM(), certFile: certificate, keyFile: key} {
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tls, err := crypto.ServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = tls
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, caFile
}

func readTLSInventory(t *testing.T, stack *shipped.Stack, cookie string) observedTLSInventory {
	t.Helper()
	code, body := stack.Do(t, cookie, http.MethodGet, "/v1/tls/posture", nil)
	var out observedTLSInventory
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || !out.Running {
		t.Fatalf("could not read the active TLS posture collector: status %d", code)
	}
	return out
}

func checkTLSInventory(t *testing.T, lane observedTLSLane, got observedTLSInventory) {
	t.Helper()
	if !got.Running || len(got.Items) != 1 {
		t.Fatalf("expected exactly one owned TLS observation, got %+v", got)
	}
	posture := got.Items[0]
	if posture.Target != lane.target || posture.Source != "http" || posture.State != threat.PostureObserved ||
		posture.Visibility != "synthetic_handshake" || posture.Freshness != "current" || posture.TLSVersion == "" ||
		posture.Cipher == "" || posture.Leaf == nil || posture.Leaf.Subject != lane.subject || posture.Leaf.Issuer != lane.issuer ||
		posture.Leaf.SerialNumber != lane.serial || !posture.Leaf.NotAfter.Equal(lane.expiry) {
		t.Fatalf("shipped observation differs from the server's original certificate: %+v", posture)
	}
	expiring := slices.ContainsFunc(posture.Findings, func(finding threat.Finding) bool { return finding.Kind == threat.FindingExpiringSoon })
	if expiring != lane.shouldWarn || slices.ContainsFunc(posture.Findings, func(finding threat.Finding) bool {
		return finding.Kind == threat.FindingUntrustedChain
	}) {
		t.Fatalf("wrong expiry or verification findings for %s: %+v", lane.target, posture.Findings)
	}
	if expiring && (posture.Handoff == nil || posture.Handoff.Serial != lane.serial || posture.Handoff.Target != lane.target) {
		t.Fatal("the expiry handoff does not refer to the exact observed leaf")
	}
}

type observedIntelFeed struct {
	Name        string
	Status      string
	LastSuccess string `json:"last_success"`
	IOCCount    int    `json:"ioc_count"`
	cacheCount  int
	AUP         struct {
		License       string
		CommercialUse string `json:"commercial_use"`
	}
}

type observedIntelStatus struct {
	Feeds    []observedIntelFeed `json:"threat_intel_feeds"`
	IOCCount int                 `json:"ioc_count"`
}

func (status observedIntelStatus) sslbl(t *testing.T) observedIntelFeed {
	t.Helper()
	for _, feed := range status.Feeds {
		if feed.Name == "sslbl" {
			feed.cacheCount = status.IOCCount
			return feed
		}
	}
	t.Fatal("the configured SSLBL descriptor is unavailable")
	return observedIntelFeed{}
}

func readObservedSSLBL(t *testing.T, stack *shipped.Stack, cookie string) observedIntelFeed {
	t.Helper()
	code, body := stack.Do(t, cookie, http.MethodGet, "/v1/threat/intel/status", nil)
	var result observedIntelStatus
	if code != http.StatusOK || json.Unmarshal(body, &result) != nil {
		t.Fatalf("read shared SSLBL refresh status = HTTP %d", code)
	}
	return result.sslbl(t)
}

func proveShippedTLSIntel(t *testing.T, stack *shipped.Stack, lanes [2]observedTLSLane, feedPath, fingerprint string) {
	t.Helper()
	owner, sibling := lanes[0], lanes[1]
	type detectionList struct{ Items []threat.Detection }
	ownedMatch := func(items []threat.Detection) (threat.Detection, bool) {
		for _, item := range items {
			if item.Indicator == fingerprint && item.Source == "sslbl" {
				return item, true
			}
		}
		return threat.Detection{}, false
	}
	readDetections := func(lane observedTLSLane) detectionList {
		code, body := stack.Do(t, lane.cookie, http.MethodGet, "/v1/threat/detections", nil)
		var got detectionList
		if code != http.StatusOK || json.Unmarshal(body, &got) != nil {
			t.Fatalf("read scoped threat detections = HTTP %d", code)
		}
		return got
	}
	var detection threat.Detection
	shipped.Await(t, "the owned observed certificate matched the cached SSLBL marker", 45*time.Second, func() bool {
		var found bool
		detection, found = ownedMatch(readDetections(owner).Items)
		return found
	})
	if detection.Confidence != 95 || detection.License != "abuse.ch CC0" || detection.Entity != owner.target ||
		detection.Type != "cert_sha1" || detection.IncidentID == "" || detection.ObservedAt.IsZero() {
		t.Fatalf("certificate match lost the observed target, clock or exact provenance: %+v", detection)
	}
	for _, lane := range lanes {
		status := readObservedSSLBL(t, stack, lane.cookie)
		if status.IOCCount != 1 || status.cacheCount != 1 || status.Status != "ok" || status.LastSuccess == "" ||
			status.AUP.License != "SSLBL CC0 1.0" || status.AUP.CommercialUse != "allowed" {
			t.Fatalf("published source metadata does not match the controlled mirror: %+v", status)
		}
		var cli observedIntelStatus
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.token}, &cli, "threat", "intel-status")
		if feed := cli.sslbl(t); feed.Status != status.Status || feed.IOCCount != status.IOCCount ||
			feed.cacheCount != status.cacheCount || feed.AUP != status.AUP {
			t.Fatalf("CLI lost the configured feed's health, IOC count or licensing: %+v", feed)
		}
	}
	if _, found := ownedMatch(readDetections(sibling).Items); found {
		t.Fatal("the sibling read the owned certificate match")
	}
	if code, _ := stack.Do(t, sibling.cookie, http.MethodGet, "/v1/incidents/"+detection.IncidentID, nil); code != http.StatusNotFound {
		t.Fatalf("sibling incident lookup returned HTTP %d, want 404", code)
	}
	var cli detectionList
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": owner.token}, &cli, "threat", "detections")
	if item, found := ownedMatch(cli.Items); !found || item.IncidentID != detection.IncidentID {
		t.Fatal("CLI lost the exact owned certificate match")
	}
	if err := os.Remove(feedPath); err != nil {
		t.Fatal(err)
	}
	shipped.Await(t, "SSLBL mirror degrades while retaining the last successful refresh", 15*time.Second, func() bool {
		status := readObservedSSLBL(t, stack, sibling.cookie)
		return status.Status == "degraded" && status.IOCCount == 1 && status.cacheCount == 1 && status.LastSuccess != ""
	})
}

func provePublishedSSLBLArchive(t *testing.T, stack *shipped.Stack, lanes [2]observedTLSLane, feedPath string) {
	t.Helper()
	source := os.Getenv("PROBECTL_TEST_SSLBL_PUBLISHED_FILE")
	if source == "" {
		return
	}
	count, err := strconv.Atoi(os.Getenv("PROBECTL_TEST_SSLBL_PUBLISHED_COUNT"))
	if err != nil || count < 1 || !filepath.IsAbs(source) {
		t.Fatal("an absolute publisher archive and its independently counted rows are required")
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal("open the publisher archive", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 8<<20 {
		t.Fatal("the bounded publisher archive is unreadable", err)
	}
	next := feedPath + ".incoming"
	if err := os.WriteFile(next, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, feedPath); err != nil {
		t.Fatal(err)
	}
	shipped.Await(t, "the shared SSLBL cache loaded the exact publisher row count", 30*time.Second, func() bool {
		for _, lane := range lanes {
			status := readObservedSSLBL(t, stack, lane.cookie)
			if status.Status != "ok" || status.LastSuccess == "" || status.IOCCount != count || status.cacheCount != count ||
				status.AUP.License != "SSLBL CC0 1.0" || status.AUP.CommercialUse != "allowed" {
				return false
			}
		}
		return true
	})
	if err := os.Remove(feedPath); err != nil {
		t.Fatal(err)
	}
	shipped.Await(t, "the exact published SSLBL count survives a mirror failure", 20*time.Second, func() bool {
		for _, lane := range lanes {
			status := readObservedSSLBL(t, stack, lane.cookie)
			if status.Status != "degraded" || status.LastSuccess == "" || status.IOCCount != count || status.cacheCount != count {
				return false
			}
		}
		return true
	})
	for i, lane := range lanes {
		status := readObservedSSLBL(t, stack, lane.cookie)
		var cli observedIntelStatus
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.token}, &cli, "threat", "intel-status")
		if feed := cli.sslbl(t); feed != status {
			t.Fatalf("CLI lost the retained archive count, health or freshness: %+v", feed)
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/security", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
			Theme: []string{"light", "dark"}[i], Accessibility: true,
			Expect: []string{"Threat-intel feed status", "SSLBL CC0 1.0", "degraded"},
			Absent: []string{lanes[1-i].target},
		})
	}
	t.Logf("published SSLBL archive retained %d independently counted certificate indicators", count)
}
