// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

func TestSIEMStatusAPIIsSanitized(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:         ":0",
		HSTSEnabled:      true,
		HSTSMaxAge:       time.Hour,
		AuthMode:         "dev",
		SIEMEnabled:      true,
		SIEMPreset:       "splunk",
		SIEMEndpoint:     "https://splunk.example:8088/services/collector/raw?token=nope",
		SIEMToken:        "super-secret-token",
		SIEMPollInterval: 15 * time.Second,
		SIEMBufferSize:   64,
		SIEMRedactKeys:   []string{"customer_email"},
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), fakePinger{}, nil, nil, nil)
	rec := do(srv, http.MethodGet, "/v1/siem/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	var got siemStatus
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.SIEMRunning || !got.Enabled || !got.Configured {
		t.Fatalf("status should report running configured export: %+v", got)
	}
	if got.Preset != "splunk" || got.Format != "cef" || got.EndpointHost != "splunk.example:8088" {
		t.Fatalf("unexpected SIEM posture: %+v", got)
	}
	if !got.EndpointConfigured || !got.EndpointTLSConfigured || !got.TokenConfigured {
		t.Fatalf("configured/token/TLS flags missing: %+v", got)
	}
	if got.AuditPollInterval != "15s" || got.BufferSize != 64 {
		t.Fatalf("poll/buffer posture = %+v", got)
	}
	if got.RedactKeyCount <= len(defaultRedactKeys) {
		t.Fatalf("redact count did not include custom keys: %+v", got)
	}

	for _, leak := range []string{"super-secret-token", "collector/raw", "token=nope"} {
		if strings.Contains(body, leak) {
			t.Fatalf("SIEM status leaked secret endpoint detail %q in %s", leak, body)
		}
	}
}

func TestSIEMStatusAPIDisabled(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/siem/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got siemStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Enabled || got.Configured || got.SIEMRunning || got.Reason != "disabled" {
		t.Fatalf("disabled status = %+v", got)
	}
	if got.AuditPollInterval != defaultSIEMAuditPollInterval.String() || got.BufferSize != defaultSIEMBufferSize {
		t.Fatalf("disabled defaults = %+v", got)
	}
}

func TestSIEMStatusRequiresHTTPSEndpoint(t *testing.T) {
	got := siemStatusFromConfig(&config.Config{
		SIEMEnabled:  true,
		SIEMEndpoint: "http://siem.example/ingest",
	})
	if got.Configured || got.SIEMRunning || got.Reason != "insecure_endpoint" || got.EndpointTLSConfigured {
		t.Fatalf("insecure endpoint status = %+v", got)
	}
}
