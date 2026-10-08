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
