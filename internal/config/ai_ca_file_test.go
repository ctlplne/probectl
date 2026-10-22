// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestAIModelCAFileFailsClosed pins the private-CA knob for the AI model
// endpoint: a valid PEM bundle loads, while a missing or certificate-less bundle
// refuses startup. The alternative — accepting a broken bundle — would let
// buildModel silently degrade to the builtin model and hide the misconfiguration.
func TestAIModelCAFileFailsClosed(t *testing.T) {
	base := map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "openai",
		"PROBECTL_AI_MODEL_ENDPOINT": "https://llm-gateway.example.internal",
		"PROBECTL_AI_MODEL_NAME":     "gpt-test",
		"PROBECTL_AI_EGRESS_ACK":     AIEgressAckPhrase,
	}
	with := func(caFile string) map[string]string {
		env := map[string]string{"PROBECTL_AI_MODEL_CA_FILE": caFile}
		for k, v := range base {
			env[k] = v
		}
		return env
	}
	dir := t.TempDir()

	if _, err := Load(envFunc(with(filepath.Join(dir, "missing.pem")))); err == nil ||
		!strings.Contains(err.Error(), "PROBECTL_AI_MODEL_CA_FILE") {
		t.Errorf("a missing CA bundle must refuse startup, got %v", err)
	}

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(envFunc(with(empty))); err == nil ||
		!strings.Contains(err.Error(), "PROBECTL_AI_MODEL_CA_FILE") {
		t.Errorf("a certificate-less CA bundle must refuse startup, got %v", err)
	}

	ca, err := crypto.GenerateCA("probectl-test-llm-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "llm-ca.pem")
	if err := os.WriteFile(good, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(envFunc(with(good)))
	if err != nil {
		t.Fatalf("a valid CA bundle was rejected: %v", err)
	}
	if cfg.AIModelCAFile != good {
		t.Errorf("AIModelCAFile = %q, want %q", cfg.AIModelCAFile, good)
	}
}

// TestAlertCAFilesFailClosed pins the DPR-290 trust bundles for alert
// delivery: a valid bundle loads, a missing or certificate-less one refuses
// startup, and an SMTP bundle without an SMTP address is a misconfiguration.
func TestAlertCAFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl-test-alert-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "alert-ca.pem")
	if err := os.WriteFile(good, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	smtp := map[string]string{"PROBECTL_ALERT_SMTP_ADDR": "relay.example.test:587", "PROBECTL_ALERT_SMTP_FROM": "probectl@example.test"}
	with := func(base map[string]string, k, v string) map[string]string {
		env := map[string]string{k: v}
		for bk, bv := range base {
			env[bk] = bv
		}
		return env
	}
	for _, key := range []string{"PROBECTL_ALERT_SMTP_CA_FILE", "PROBECTL_ALERT_WEBHOOK_CA_FILE"} {
		for _, bad := range []string{filepath.Join(dir, "missing.pem"), empty} {
			if _, err := Load(envFunc(with(smtp, key, bad))); err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s=%s must refuse startup naming the key, got %v", key, filepath.Base(bad), err)
			}
		}
	}
	cfg, err := Load(envFunc(with(with(smtp, "PROBECTL_ALERT_SMTP_CA_FILE", good), "PROBECTL_ALERT_WEBHOOK_CA_FILE", good)))
	if err != nil {
		t.Fatalf("valid alert CA bundles refused: %v", err)
	}
	if cfg.AlertSMTPCAFile != good || cfg.AlertWebhookCAFile != good {
		t.Fatalf("alert CA bundles not applied: smtp=%q webhook=%q", cfg.AlertSMTPCAFile, cfg.AlertWebhookCAFile)
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_ALERT_SMTP_CA_FILE": good})); err == nil {
		t.Error("an SMTP CA bundle without PROBECTL_ALERT_SMTP_ADDR must be refused as a misconfiguration")
	}
}
