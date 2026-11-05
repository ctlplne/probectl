// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
)

func (p *releaseFlowReport) preparePacketIdentity(t *testing.T, cli func(...string) string, agent, hostname, ca, address string, env map[string]string) {
	t.Helper()
	if address == "" {
		t.Fatal("real packet metadata requires the existing mTLS evidence listener")
	}
	csr, key, err := crypto.CreateCSR("release-packet-evidence")
	if err != nil {
		t.Fatal("create owned packet evidence CSR:", err)
	}
	defer clear(key)
	token := mintEnrollTokenTTL(t, cli, p.tenant, agent, hostname, "10m")
	var registration struct {
		TenantID string           `json:"tenant_id"`
		AgentID  string           `json:"agent_id"`
		Plane    string           `json:"plane"`
		SVID     *enroll.Identity `json:"svid"`
	}
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
		map[string]string{"token": token, "plane": "entity", "hostname": hostname, "csr_pem": string(csr)}, &registration)
	if registration.TenantID != p.tenant || registration.AgentID != agent || registration.Plane != "entity" ||
		registration.SVID == nil || registration.SVID.SPIFFEID != crypto.EntitySPIFFEID(p.tenant, agent) || registration.SVID.CertPEM == "" {
		t.Fatal("packet evidence registration changed its exact raw collector tenant, agent or restricted identity")
	}
	trust, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal("read public packet evidence server CA:", err)
	}
	directory := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem"), filepath.Join(directory, "server-ca.pem")
	for _, file := range []struct {
		path string
		body []byte
	}{{certFile, []byte(registration.SVID.CertPEM)}, {keyFile, key}, {caFile, trust}} {
		if err := os.WriteFile(file.path, file.body, 0o600); err != nil {
			t.Fatal("write owned packet evidence identity file:", err)
		}
	}
	env["PROBECTL_FLOW_EVIDENCE_CONTROL_ADDR"] = address
	env["PROBECTL_FLOW_EVIDENCE_ROTATE_URL"] = p.api.base + "/enroll/agent/rotate"
	env["PROBECTL_FLOW_EVIDENCE_CERT_FILE"] = certFile
	env["PROBECTL_FLOW_EVIDENCE_KEY_FILE"] = keyFile
	env["PROBECTL_FLOW_EVIDENCE_CA_FILE"] = caFile
	env["PROBECTL_FLOW_EVIDENCE_SERVER_NAME"] = "localhost"
	env["PROBECTL_FLOW_EVIDENCE_EXPORTERS"] = "127.0.0.1"
}
