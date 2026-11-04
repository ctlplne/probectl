// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// This extends the existing live Net-SNMP/shipped-binary journey. All facts
// come from the configured device agent's restricted mTLS channel; only
// configuration and tag policy are created through ordinary public APIs.
// The shared CI bus's dev profile is not a release-image TLS/SASL receipt.
type snmpTagProof struct {
	tenant                     *deviceTenant
	contextID, entityID, tagID string
	initialValue, changedValue string
	initialDescr, changedDescr string
}

func snmpTagWrite(t *testing.T, st *shipped.Stack, tn *deviceTenant, status int, method, route string, body, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, method, route, body)
	if code != status {
		// Registration bodies can contain one-time tokens. Never print them.
		t.Fatalf("SNMP metadata %s %s as %s returned %d, want %d", method, route, tn.slug, code, status)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		t.Fatal("SNMP metadata response was not the expected JSON shape")
	}
}

func prepareSNMPTagProof(t *testing.T, st *shipped.Stack, tn *deviceTenant) *snmpTagProof {
	t.Helper()
	p := &snmpTagProof{tenant: tn, initialValue: "initial-" + tn.id, changedValue: "changed-" + tn.id,
		initialDescr: tn.sysDescr, changedDescr: tn.sysDescr + " version2"}
	var routingContext struct {
		ID string `json:"context_id"`
	}
	snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/entity-contexts",
		map[string]string{"site_label": "same SNMP site", "vrf_label": "same SNMP VRF"}, &routingContext)
	p.contextID = routingContext.ID
	var target struct{ ID string }
	snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/entities",
		map[string]string{"context_id": p.contextID, "kind": "device", "label": "same SNMP router"}, &target)
	p.entityID = target.ID
	if p.contextID == "" || p.entityID == "" {
		t.Fatal("SNMP metadata fixture has no owned context or canonical device")
	}
	csr, key, err := crypto.CreateCSR(tn.sysName + "-entity")
	if err != nil {
		t.Fatal("generate collector-owned evidence CSR:", err)
	}
	tn.evidenceKey = string(key)
	var token struct{ Token string }
	snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/agents/enroll-tokens",
		map[string]any{"agent_id": tn.collectorID, "name": tn.sysName + "-entity", "ttl_seconds": 600}, &token)
	var issued enroll.CollectorIdentity
	snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
		map[string]string{"token": token.Token, "plane": "entity", "hostname": tn.sysName, "csr_pem": string(csr)}, &issued)
	if issued.TenantID != tn.id || issued.AgentID != tn.collectorID || issued.Plane != "entity" || issued.SVID == nil ||
		issued.SVID.SPIFFEID != crypto.EntitySPIFFEID(tn.id, tn.collectorID) || issued.SVID.Serial == "" ||
		issued.SVID.CertPEM == "" || issued.SVID.CABundle == "" {
		t.Fatal("additional evidence SVID did not retain the existing collector's exact tenant and identity")
	}
	dir := filepath.Join(st.Dir, "device-evidence-"+tn.slug)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	serverCA, err := os.ReadFile(st.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"key.pem": key, "cert.pem": []byte(issued.SVID.CertPEM),
		"ca.pem": []byte(issued.SVID.CABundle), "server-ca.pem": serverCA} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tn.evidence = map[string]string{"control_addr": st.AgentAddr, "rotate_url": st.BaseURL,
		"cert_file": filepath.Join(dir, "cert.pem"), "key_file": filepath.Join(dir, "key.pem"),
		"ca_file": filepath.Join(dir, "server-ca.pem"), "server_name": "localhost"}
	p.assignSource(t, st, p.contextID, p.entityID)
	var definition struct{ ID string }
	snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/tags", map[string]string{"key": "snmp_firmware"}, &definition)
	p.tagID = definition.ID
	if p.tagID == "" {
		t.Fatal("SNMP tag has no owned definition")
	}
	for _, rule := range []struct{ descr, value string }{{p.initialDescr, p.initialValue}, {p.changedDescr, p.changedValue}} {
		snmpTagWrite(t, st, tn, http.StatusCreated, http.MethodPost, "/v1/entity-contexts/"+p.contextID+"/tag-rules",
			map[string]string{"tag_id": p.tagID, "target_kind": "device", "match_kind": "snmp_field",
				"snmp_field": "sys_descr", "snmp_value": rule.descr, "value": rule.value}, nil)
	}
	return p
}

func (p *snmpTagProof) assignSource(t *testing.T, st *shipped.Stack, contextID, entityID string) {
	t.Helper()
	snmpTagWrite(t, st, p.tenant, http.StatusOK, http.MethodPut, "/v1/entity-source-contexts",
		map[string]string{"agent_id": p.tenant.collectorID, "source_kind": "device_target", "source_ref": "127.0.0.1",
			"context_id": contextID, "anchor_entity_id": entityID}, nil)
}

func (p *snmpTagProof) read(t *testing.T, st *shipped.Stack) tags.SubjectResolution {
	t.Helper()
	var out tags.SubjectResolution
	p.tenant.get(t, st, "/v1/entity-contexts/"+p.contextID+"/resolved-tags?target_kind=device&target_id="+p.entityID, &out)
	if revision, err := strconv.ParseUint(out.TagRevision, 10, 64); err != nil || revision == 0 {
		t.Fatal("SNMP tag read lost its exact current decimal revision")
	}
	if _, err := time.Parse(time.RFC3339Nano, out.AsOf); err != nil || out.ContextID != p.contextID || out.TargetKind != "device" || out.TargetID != p.entityID {
		t.Fatal("SNMP tag read lost its exact owned subject or current as-of")
	}
	return out
}

func (p *snmpTagProof) matches(out tags.SubjectResolution, value, source string) bool {
	if value == "" {
		return len(out.Items) == 0
	}
	return len(out.Items) == 1 && out.Items[0].TagID == p.tagID && out.Items[0].Key == "snmp_firmware" &&
		out.Items[0].Value == value && out.Items[0].Source == source
}

func (p *snmpTagProof) requireValue(t *testing.T, st *shipped.Stack, value, source string) {
	t.Helper()
	if !p.matches(p.read(t, st), value, source) {
		t.Fatal("sender-attested SNMP tag metadata lost the exact current owned value or source")
	}
}

func (p *snmpTagProof) awaitValue(t *testing.T, st *shipped.Stack, value, source string) {
	t.Helper()
	shipped.Await(t, "sender-attested SNMP tag metadata "+p.tenant.slug, 120*time.Second, func() bool {
		return p.matches(p.read(t, st), value, source)
	})
}

func proveSNMPTagMetadata(t *testing.T, st *shipped.Stack, a, b *snmpTagProof) {
	t.Helper()
	if a.contextID == b.contextID || a.entityID == b.entityID || a.tagID == b.tagID {
		t.Fatal("equal SNMP target and metadata labels collapsed tenant identities")
	}
	current := map[*snmpTagProof]string{a: a.initialValue, b: b.initialValue}
	for _, pair := range [][2]*snmpTagProof{{a, b}, {b, a}} {
		p, foreign := pair[0], pair[1]
		initial := p.read(t, st)
		if !p.matches(initial, p.initialValue, "rule") {
			t.Fatal("live SNMP metadata lost its initial owned rule")
		}
		var fromCLI tags.SubjectResolution
		p.tenant.cli(t, st, &fromCLI, "tags", "resolve", p.contextID, "--query", "target_kind=device", "--query", "target_id="+p.entityID)
		if !p.matches(fromCLI, p.initialValue, "rule") || fromCLI.ContextID != p.contextID || fromCLI.TargetKind != "device" || fromCLI.TargetID != p.entityID || fromCLI.TagRevision != initial.TagRevision {
			t.Fatal("real CLI lost collected SNMP tag metadata or owned subject")
		}
		if _, err := time.Parse(time.RFC3339Nano, fromCLI.AsOf); err != nil {
			t.Fatal("real CLI lost the SNMP tag current as-of")
		}
		for _, route := range []string{
			"/v1/entity-contexts/" + foreign.contextID + "/resolved-tags?target_kind=device&target_id=" + foreign.entityID,
			"/v1/entity-contexts/" + p.contextID + "/resolved-tags?target_kind=device&target_id=" + foreign.entityID,
		} {
			code, raw := st.Do(t, p.tenant.cookie, http.MethodGet, route, nil)
			p.tenant.keep(raw)
			if code != http.StatusNotFound {
				t.Fatal("foreign SNMP tag subject or context was not hidden", code)
			}
		}
		// Reload only this owned target's public description; its live SNMP
		// engine and ordinary configured poll must supply the changed fact.
		p.tenant.device.lab.docker(t, "exec", p.tenant.device.container, "sed", "-i",
			"/^sysDescr /c\\sysDescr "+p.changedDescr, "/etc/snmp/snmpd.conf")
		p.tenant.device.lab.docker(t, "kill", "--signal", "HUP", p.tenant.device.container)
		p.awaitValue(t, st, p.changedValue, "rule")
		foreign.requireValue(t, st, current[foreign], "rule")
		var manual struct{ ID string }
		path := "/v1/entity-contexts/" + p.contextID + "/tag-assignments"
		snmpTagWrite(t, st, p.tenant, http.StatusCreated, http.MethodPost, path,
			map[string]string{"tag_id": p.tagID, "target_kind": "device", "target_id": p.entityID, "value": "manual-" + p.tenant.id}, &manual)
		p.requireValue(t, st, "manual-"+p.tenant.id, "manual")
		if manual.ID == "" {
			t.Fatal("manual SNMP tag assignment has no identity")
		}
		snmpTagWrite(t, st, p.tenant, http.StatusNoContent, http.MethodDelete, path+"/"+manual.ID, nil, nil)
		p.requireValue(t, st, p.changedValue, "rule")
		// Moving the source must retire its old subject's automatic facts.
		var nextContext struct {
			ID string `json:"context_id"`
		}
		snmpTagWrite(t, st, p.tenant, http.StatusCreated, http.MethodPost, "/v1/entity-contexts",
			map[string]string{"site_label": "replacement SNMP site", "vrf_label": "replacement SNMP VRF"}, &nextContext)
		var nextDevice struct{ ID string }
		snmpTagWrite(t, st, p.tenant, http.StatusCreated, http.MethodPost, "/v1/entities",
			map[string]string{"context_id": nextContext.ID, "kind": "device", "label": "replacement SNMP device"}, &nextDevice)
		p.assignSource(t, st, nextContext.ID, nextDevice.ID)
		p.requireValue(t, st, "", "")
		current[p] = ""
	}
}
