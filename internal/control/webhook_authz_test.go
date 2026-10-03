// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/logging"
)

// testWebhookSecret is a >= 32-byte secret (AUTHZ-19 floor) for the unit tests
// that construct a Server.cfg directly (bypassing config.Load).
const testWebhookSecret = "unit-test-webhook-secret-0123456789"

// genericSignedHeaders builds valid generic-provider signature headers. An empty
// deliveryID omits the delivery-id header (the "missing delivery id" case).
func genericSignedHeaders(secret string, body []byte, deliveryID string, now time.Time) map[string]string {
	ts := strconv.FormatInt(now.Unix(), 10)
	payload := append(append([]byte(ts), '.'), body...)
	h := map[string]string{
		change.GenericTimestampHeader: ts,
		change.GenericSignatureHeader: "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), payload)),
	}
	if deliveryID != "" {
		h[change.GenericDeliveryIDHeader] = deliveryID
	}
	return h
}

// AUTHZ-19 (sub-issue 1): every pre-verification rejection of the change-webhook
// ingress returns the ONE identical 401 body — unknown id, bad signature and a
// missing delivery id are indistinguishable — so the response cannot be used as
// an oracle to tell a valid credential id apart from an invalid one.
func TestChangeWebhookPreVerificationUnauthorizedIsByteIdentical(t *testing.T) {
	const id = "wh1"
	srv := &Server{cfg: &config.Config{ChangeWebhooks: map[string]config.ChangeWebhook{
		id: {TenantID: "00000000-0000-0000-0000-000000000001", Provider: "generic", Secret: testWebhookSecret},
	}}}
	body := []byte(`{"kind":"deploy","title":"x","target":"api.example.com"}`)
	now := time.Now().UTC()

	post := func(reqID string, headers map[string]string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/ingest/changes/generic/"+reqID, bytes.NewReader(body))
		req.SetPathValue("provider", "generic")
		req.SetPathValue("id", reqID)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		apiHandler(srv.handleChangeWebhook).ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// (1) unknown id — never resolves a credential.
	unknownCode, unknownBody := post("no-such-id", genericSignedHeaders(testWebhookSecret, body, "delivery-1", now))
	// (2) known id, fresh timestamp, WRONG signature.
	badSigCode, badSigBody := post(id, map[string]string{
		change.GenericTimestampHeader: strconv.FormatInt(now.Unix(), 10),
		change.GenericSignatureHeader: "sha256=deadbeef",
	})
	// (3) known id, VALID signature, but NO delivery-id header.
	missingDelCode, missingDelBody := post(id, genericSignedHeaders(testWebhookSecret, body, "", now))

	for _, c := range []struct {
		name string
		code int
	}{
		{"unknown-id", unknownCode},
		{"bad-signature", badSigCode},
		{"missing-delivery-id", missingDelCode},
	} {
		if c.code != http.StatusUnauthorized {
			t.Fatalf("%s: code = %d, want 401", c.name, c.code)
		}
	}
	if unknownBody != badSigBody || unknownBody != missingDelBody {
		t.Fatalf("pre-verification 401 bodies must be byte-identical (enumeration oracle):\n unknown-id=%q\n bad-signature=%q\n missing-delivery-id=%q",
			unknownBody, badSigBody, missingDelBody)
	}
}

// AUTHZ-19 (sub-issue 1): the ITSM ingress shares the exact same generic 401 for
// unknown id and bad signature.
func TestITSMWebhookPreVerificationUnauthorizedIsByteIdentical(t *testing.T) {
	const id = "snow1"
	srv := &Server{cfg: &config.Config{NotifyInbound: map[string]config.NotifyInbound{
		id: {TenantID: "00000000-0000-0000-0000-000000000001", Provider: "servicenow", Secret: testWebhookSecret},
	}}}
	body := []byte(`{"external_ref":"INC1","resolved":true}`)

	post := func(reqID string, headers map[string]string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/"+reqID, bytes.NewReader(body))
		req.SetPathValue("provider", "servicenow")
		req.SetPathValue("id", reqID)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		apiHandler(srv.handleITSMWebhook).ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	unknownCode, unknownBody := post("no-such-id", nil) // unknown id
	badSigCode, badSigBody := post(id, nil)             // known id, no/forged signature

	if unknownCode != http.StatusUnauthorized || badSigCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for both; unknown=%d badsig=%d", unknownCode, badSigCode)
	}
	if unknownBody != badSigBody {
		t.Fatalf("ITSM pre-verification 401 bodies must be byte-identical:\n unknown-id=%q\n bad-signature=%q", unknownBody, badSigBody)
	}
}

// AUTHZ-19 (sub-issue 5): the unauthenticated webhook ingress is rate-limited.
// N failed deliveries from one source IP lock that source (429 + Retry-After);
// the same credential id is locked across source IPs (per-credential dimension);
// a fresh IP on a fresh id is unaffected (per-source-IP dimension).
func TestWebhookIngressThrottlesBruteForce(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr: ":0", AuthMode: "session",
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthRateMaxFailures: 3, AuthRateWindow: time.Minute, AuthRateLockout: time.Minute,
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	hit := func(remote, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ingest/changes/generic/"+id, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// The first maxFailures (3) unknown-id deliveries from one IP are counted (401);
	// the next from that IP is locked (429 + Retry-After).
	for i := 0; i < 3; i++ {
		if rec := hit("198.51.100.42:9", "guess-me"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d, want 401", i+1, rec.Code)
		}
	}
	locked := hit("198.51.100.42:9", "guess-me")
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("post-budget attempt: code = %d, want 429", locked.Code)
	}
	if locked.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	// A DIFFERENT source IP hammering the SAME credential id is also locked (the
	// per-credential-id dimension bounds brute-forcing one id across many IPs).
	if rec := hit("203.0.113.77:9", "guess-me"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("cross-IP same-credential: code = %d, want 429", rec.Code)
	}
	// A fresh IP on a fresh credential id is unaffected (per-source-IP dimension).
	if rec := hit("203.0.113.77:9", "another-id"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fresh source + fresh id: code = %d, want 401 (not throttled)", rec.Code)
	}
}
