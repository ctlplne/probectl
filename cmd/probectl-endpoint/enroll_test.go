// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestEndpointEnrollmentChecksExistingTenantBeforeReadingToken(t *testing.T) {
	for _, key := range []string{"PROBECTL_ENDPOINT_TENANT_ID", "PROBECTL_ENDPOINT_CONTROL_ADDR",
		"PROBECTL_ENDPOINT_ENROLLMENT_URL", "PROBECTL_ENDPOINT_IDENTITY_DIR", "PROBECTL_ENDPOINT_BUS_MODE",
		"PROBECTL_ENDPOINT_BUS_NAMESPACE", "PROBECTL_ENDPOINT_BUS_BROKERS"} {
		t.Setenv(key, "")
	}
	const owner = "11111111-1111-4111-8111-111111111111"
	const sibling = "22222222-2222-4222-8222-222222222222"
	const agentID = "33333333-3333-4333-8333-333333333333"
	ca, err := crypto.GenerateCA("endpoint enrollment fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(owner, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "identity")
	if store := endpointEnrollmentStore(identity); store != nil {
		if err := store.Save(agent.EnrollmentMaterial{
			Certificate: cert, PrivateKey: key, IssuerCA: ca.CertPEM(), ServerCA: ca.CertPEM(),
		}); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.Mkdir(identity, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			agent.IdentityCertFile: cert, agent.IdentityKeyFile: key,
			agent.IdentityCAFile: ca.CertPEM(), agent.IdentityServerCAFile: ca.CertPEM(),
		} {
			if err := os.WriteFile(filepath.Join(identity, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	otherCA, err := crypto.GenerateCA("other control-plane fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeBundle := func(pem []byte) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), "control-ca.pem")
		if err := os.WriteFile(file, pem, 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	matching := writeBundle(append([]byte("\n"), ca.CertPEM()...))
	foreign := writeBundle(otherCA.CertPEM())
	for _, tt := range []struct {
		tenant, caFile, wantErr string
	}{
		{tenant: owner},
		{tenant: owner, caFile: matching},
		{tenant: owner, caFile: foreign, wantErr: "differs from the enrolled device's control-plane trust"},
		{tenant: sibling, caFile: matching, wantErr: "expected tenant"},
	} {
		path := filepath.Join(t.TempDir(), "endpoint.yaml")
		yaml := fmt.Sprintf("apiVersion: probectl.io/endpoint/v1\ntenant_id: %s\ncontrol:\n  address: owned.example:8444\n  enrollment_url: https://owned.example\n  identity_dir: %q\n",
			tt.tenant, identity)
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		input := strings.NewReader("a token that must never be read")
		initial := input.Len()
		args := []string{"--config", path}
		if tt.caFile != "" {
			args = append(args, "--ca-file", tt.caFile)
		}
		err := runEndpointEnroll(args, input, io.Discard)
		if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Fatalf("enroll with existing identity on %s, want error %q: %v", tt.tenant, tt.wantErr, err)
		}
		if input.Len() != initial {
			t.Fatal("an enrollment retry or foreign identity consumed token input")
		}
	}
	token := "pjt_" + strings.Repeat("a", 64)
	if err := runEndpointEnroll([]string{"--token", token}, strings.NewReader(""), io.Discard); err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("endpoint enrollment accepted or disclosed a command-line token")
	}
	t.Run("server rejection", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, token)
		}))
		defer server.Close()
		root := t.TempDir()
		certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		caFile := filepath.Join(root, "control-ca.pem")
		if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(root, "endpoint.yaml")
		yaml := fmt.Sprintf("apiVersion: probectl.io/endpoint/v1\ntenant_id: %s\ncontrol:\n  address: owned.example:8444\n  enrollment_url: %s\n  identity_dir: %q\n",
			owner, server.URL, filepath.Join(root, "identity"))
		if err := os.WriteFile(config, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		err := runEndpointEnroll([]string{"--config", config, "--ca-file", caFile}, strings.NewReader(token), io.Discard)
		if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "HTTP 401") {
			t.Fatal("enrollment rejection did not retain its status or disclosed the response body")
		}
	})
}
