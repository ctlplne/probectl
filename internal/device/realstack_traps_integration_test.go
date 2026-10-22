// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The trap read model (D-60) and trap alert rules (D-61) legs of the F18
// receipt: what the control plane stored of each tenant's authenticated
// traps, read back through the API and the CLI, and the tenant's trap rule
// firing to the tenant's own webhook receiver only.

const (
	oidLinkDown  = ".1.3.6.1.6.3.1.1.5.3"
	oidLinkUp    = ".1.3.6.1.6.3.1.1.5.4"
	oidIfIndex   = ".1.3.6.1.2.1.2.2.1.1"
	trapEval     = 2 * time.Second
	trapDelivery = 90 * time.Second
)

// trapRow is one GET /v1/device/traps item.
type trapRow struct {
	ID            string `json:"id"`
	AgentID       string `json:"agent_id"`
	DeviceAddress string `json:"device_address"`
	SourceAddress string `json:"source_address"`
	AuthPrincipal string `json:"auth_principal"`
	Version       string `json:"version"`
	Kind          string `json:"kind"`
	Severity      string `json:"severity"`
	TrapOID       string `json:"trap_oid"`
	TrapName      string `json:"trap_name"`
	IfIndex       uint32 `json:"if_index"`
	VarBinds      []struct {
		OID   string `json:"oid"`
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"varbinds"`
	ReceivedAt time.Time `json:"received_at"`
}

type trapList struct {
	ContractVersion   string    `json:"contract_version"`
	Items             []trapRow `json:"items"`
	CollectionRunning bool      `json:"collection_running"`
	Truncated         bool      `json:"truncated"`
}

// ownsTrapRow: the stored trap is the tenant's device's authenticated
// linkDown, attributed to the tenant's own agent and source, with the
// ifIndex varbind the device sent.
func (tn *deviceTenant) ownsTrapRow(r trapRow) bool {
	principal := tn.sysName
	if tn.transport == "snmpv3" {
		principal = tn.user
	}
	eth0 := strconv.FormatUint(uint64(tn.device.eth0), 10)
	hasIfIndex := slices.ContainsFunc(r.VarBinds, func(vb struct {
		OID   string `json:"oid"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}) bool {
		return vb.OID == oidIfIndex+"."+eth0 && vb.Value == eth0
	})
	return r.AgentID == tn.collectorID && r.Kind == "snmp.trap.link_down" && r.TrapOID == oidLinkDown &&
		r.TrapName == "linkDown" && r.Version == tn.transport && r.AuthPrincipal == principal &&
		r.IfIndex == tn.device.eth0 && r.SourceAddress == tn.trapSource && r.DeviceAddress == tn.trapSource && hasIfIndex
}

func (tn *deviceTenant) trapsAPI(t *testing.T, st *shipped.Stack, query string) trapList {
	t.Helper()
	var out trapList
	tn.get(t, st, "/v1/device/traps"+query, &out)
	return out
}

// awaitStoredTrap waits until the tenant's own trap is readable through the
// API — the bus → consumer → forced-RLS table path. A timeout is reported and
// the receipt goes on, so the alert leg is still judged when the read is broken.
func (tn *deviceTenant) awaitStoredTrap(t *testing.T, st *shipped.Stack, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !slices.ContainsFunc(tn.trapsAPI(t, st, "?limit=500").Items, tn.ownsTrapRow) {
		if time.Now().After(deadline) {
			t.Errorf("GET /v1/device/traps as %s never listed its device's linkDown within %s", tn.slug, within)
			return
		}
		time.Sleep(time.Second)
	}
}

// checkTrapSurfaces: GET /v1/device/traps and `probectl device traps` show the
// tenant exactly its one authenticated trap — neither refused trap, nothing of
// the other tenant's — and a filter for the device returns the same row.
func (tn *deviceTenant) checkTrapSurfaces(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	api := tn.trapsAPI(t, st, "?limit=500")
	var cli trapList
	tn.cli(t, st, &cli, "device", "traps", "--query", "limit=500")
	filtered := tn.trapsAPI(t, st, "?device="+tn.trapSource+"&since="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	for surface, out := range map[string]trapList{
		"GET /v1/device/traps": api, "probectl device traps": cli,
		"GET /v1/device/traps?device=&since=": filtered,
	} {
		if out.ContractVersion != "probectl.device-traps/v1" || !out.CollectionRunning || len(out.Items) != 1 || !tn.ownsTrapRow(out.Items[0]) {
			t.Errorf("%s as %s = %+v, want exactly %s's authenticated linkDown (the refused traps and the other tenant's never stored)",
				surface, tn.slug, out, tn.sysName)
			continue
		}
		t.Logf("%s as %s: %s %s from %s as %s, ifIndex %d, agent %s", surface, tn.slug, out.Items[0].Version,
			out.Items[0].TrapName, out.Items[0].SourceAddress, out.Items[0].AuthPrincipal, out.Items[0].IfIndex, out.Items[0].AgentID)
	}
	for _, other := range tenants {
		if other == tn {
			continue
		}
		for _, r := range append(api.Items, cli.Items...) {
			if r.AgentID == other.collectorID || other.ownsTrapRow(r) {
				t.Errorf("CROSS-TENANT TRAP: %s's trap list holds %s's trap: %+v", tn.slug, other.slug, r)
			}
		}
	}
}

// --- trap alert rules ---

// trapRuleBody is the tenant's trap rule: linkDown fires, linkUp clears, an
// hour's hold, delivered to the tenant's own webhook. Both tenants' rules
// match every device of their tenant (no device filter), so only the tenant
// scope keeps the other tenant's linkDown out; B's also requires the ifIndex
// varbind its device sends.
func (tn *deviceTenant) trapRuleBody(varbind bool) map[string]any {
	match := map[string]any{"trap_oid": oidLinkDown, "clear_trap_oid": oidLinkUp, "hold_seconds": 3600}
	if varbind {
		eth0 := strconv.FormatUint(uint64(tn.device.eth0), 10)
		match["varbind_oid"], match["varbind_value"] = oidIfIndex+"."+eth0, eth0
	}
	return map[string]any{
		"name": "link down " + tn.slug, "type": "trap", "severity": "critical", "trap": match,
		"channels": []map[string]any{{"type": "webhook", "url": "https://" + tn.hookHost + "/probectl/traps", "secret": tn.hookSecret}},
	}
}

type trapRuleView struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Metric string         `json:"metric"`
	Trap   map[string]any `json:"trap"`
}

// createTrapRuleAPI makes the rule through POST /v1/alerts as the tenant admin.
func (tn *deviceTenant) createTrapRuleAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/alerts", tn.trapRuleBody(false))
	tn.keep(raw)
	var rule trapRuleView
	if code != http.StatusCreated || json.Unmarshal(raw, &rule) != nil {
		t.Fatalf("POST /v1/alerts (trap rule) as %s = %d: %.400s", tn.slug, code, raw)
	}
	tn.bindTrapRule(t, "POST /v1/alerts", rule)
}

// createTrapRuleCLI makes the rule with `probectl alert create`.
func (tn *deviceTenant) createTrapRuleCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var rule trapRuleView
	tn.cli(t, st, &rule, "alert", "create", "--body-file", st.SecretFile(t, tn.trapRuleBody(true)))
	tn.bindTrapRule(t, "probectl alert create", rule)
}

func (tn *deviceTenant) bindTrapRule(t *testing.T, surface string, rule trapRuleView) {
	t.Helper()
	if rule.ID == "" || rule.Type != "trap" || rule.Metric != "probectl_device_trap" || rule.Trap["trap_oid"] != oidLinkDown ||
		rule.Trap["clear_trap_oid"] != oidLinkUp {
		t.Fatalf("%s as %s returned %+v, want the stored trap rule", surface, tn.slug, rule)
	}
	tn.trapRuleID = rule.ID
	t.Logf("%s made %s's trap rule %s (%v)", surface, tn.slug, rule.ID, rule.Trap)
}

// awaitTrapRuleEvaluated waits for the tenant's evaluator to have evaluated
// its trap rule (a no_data receipt: no matching trap yet), so the trap leg
// starts with every engine running.
func (tn *deviceTenant) awaitTrapRuleEvaluated(t *testing.T, st *shipped.Stack) {
	t.Helper()
	shipped.Await(t, tn.slug+"'s trap rule evaluating", 60*time.Second, func() bool {
		var out struct {
			Items []struct {
				State  string `json:"state"`
				RuleID string `json:"rule_id"`
			} `json:"items"`
		}
		tn.get(t, st, "/v1/alerts/"+tn.trapRuleID+"/evaluations?limit=100", &out)
		return slices.ContainsFunc(out.Items, func(e struct {
			State  string `json:"state"`
			RuleID string `json:"rule_id"`
		}) bool {
			return e.RuleID == tn.trapRuleID && e.State == "no_data"
		})
	})
}

// awaitTrapAlert waits for the tenant's receiver to hold a firing delivery of
// its trap rule.
func (tn *deviceTenant) awaitTrapAlert(t *testing.T) {
	t.Helper()
	shipped.Await(t, tn.slug+"'s trap rule firing to its own receiver", trapDelivery, func() bool {
		return slices.ContainsFunc(tn.receiver.all(), func(d hookDelivery) bool {
			return d.Payload.State == "firing" && d.Payload.Rule.ID == tn.trapRuleID
		})
	})
}

// checkTrapDeliveries: every delivery the tenant's receiver got is its own
// rule firing on its own device's linkDown, signed with its own secret, and
// free of every device credential; exactly one arrived.
func (tn *deviceTenant) checkTrapDeliveries(t *testing.T, tenants []*deviceTenant) {
	t.Helper()
	got := tn.receiver.all()
	var creds []string
	for _, x := range tenants {
		creds = append(creds, x.secrets()...)
	}
	if len(got) != 1 {
		t.Errorf("%s's receiver got %d trap-alert deliveries, want exactly its rule firing once: %s", tn.slug, len(got), describeDeliveries(got))
	}
	for _, d := range got {
		p := d.Payload
		if p.Version != "probectl.alert.v1" || p.State != "firing" || p.TenantID != tn.id || p.Rule.ID != tn.trapRuleID ||
			p.Metric != "probectl_device_trap" || p.Severity != "critical" || p.Labels["device"] != tn.trapSource ||
			p.Labels["trap_oid"] != oidLinkDown || p.Labels["trap_name"] != "linkDown" || !strings.Contains(p.Reason, "linkDown trap from "+tn.trapSource) {
			t.Errorf("%s's receiver got %+v, want its own trap rule %s firing on its device's linkDown", tn.slug, p, tn.trapRuleID)
		}
		for _, other := range tenants {
			if other == tn {
				continue
			}
			if p.TenantID == other.id || p.Rule.ID == other.trapRuleID {
				t.Errorf("CROSS-TENANT TRAP ALERT: %s's receiver got %s's alert: %+v", tn.slug, other.slug, p)
			}
			if d.Signature == "sha256="+hex.EncodeToString(crypto.Sign([]byte(other.hookSecret), d.Body)) {
				t.Errorf("%s's delivery is signed with %s's secret", tn.slug, other.slug)
			}
		}
		if want := "sha256=" + hex.EncodeToString(crypto.Sign([]byte(tn.hookSecret), d.Body)); d.Signature != want {
			t.Errorf("%s's delivery signature does not verify with its own secret", tn.slug)
		}
		for _, s := range creds {
			if bytes.Contains(d.Body, []byte(s)) {
				t.Errorf("%s's trap-alert webhook body carries a device credential (%d chars)", tn.slug, len(s))
			}
		}
		if d.Path != "/probectl/traps" {
			t.Errorf("%s's delivery went to %s", tn.slug, d.Path)
		}
		t.Logf("%s's receiver got %s %q for tenant %s: %s", tn.slug, p.State, p.Rule.Name, p.TenantID, p.Reason)
		tn.keep(d.Body)
	}
}

func describeDeliveries(ds []hookDelivery) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("%s %s tenant=%s labels=%v", d.Payload.State, d.Payload.Rule.Name, d.Payload.TenantID, d.Payload.Labels))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// --- webhook receivers, the egress proxy and the receipt CA (the F8 shape) ---

type hookPayload struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Rule    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rule"`
	TenantID string            `json:"tenant_id"`
	Severity string            `json:"severity"`
	Metric   string            `json:"metric"`
	Labels   map[string]string `json:"labels"`
	Value    float64           `json:"value"`
	Reason   string            `json:"reason"`
}

type hookDelivery struct {
	Path, Signature string
	Body            []byte
	Payload         hookPayload
}

// hookReceiver is one tenant's webhook endpoint: HTTPS with a certificate for
// its public name under the receipt's CA, recording every delivery.
type hookReceiver struct {
	addr string
	mu   sync.Mutex
	got  []hookDelivery
}

func startHookReceiver(t *testing.T, pki *receiptPKI, host string) *hookReceiver {
	t.Helper()
	h := &hookReceiver{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		d := hookDelivery{Path: r.URL.Path, Signature: r.Header.Get("X-Probectl-Signature"), Body: body}
		if r.Method != http.MethodPost || json.Unmarshal(body, &d.Payload) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.got = append(h.got, d)
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = pki.serverTLS(t, host)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.addr = srv.Listener.Addr().String()
	return h
}

func (h *hookReceiver) all() []hookDelivery {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookDelivery(nil), h.got...)
}

// egressProxy is the deployment's HTTP CONNECT egress proxy: it resolves the
// receivers' public names to where they live and refuses everything else.
type egressProxy struct {
	addr  string
	mu    sync.Mutex
	hosts map[string]bool
}

func startEgressProxy(t *testing.T, routes map[string]string) *egressProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &egressProxy{addr: ln.Addr().String(), hosts: map[string]bool{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.tunnel(conn, routes)
		}
	}()
	return p
}

func (p *egressProxy) tunnel(conn net.Conn, routes map[string]string) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	upstream, ok := routes[req.Host]
	if req.Method != http.MethodConnect || !ok {
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", upstream)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	host, _, _ := net.SplitHostPort(req.Host)
	p.mu.Lock()
	p.hosts[host] = true
	p.mu.Unlock()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	go func() { _, _ = io.Copy(up, conn) }()
	_, _ = io.Copy(conn, up)
}

func (p *egressProxy) tunneled() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.hosts))
	for h := range p.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// receiptPKI is the receipt's own CA for the receivers' certificates, trusted
// by the control plane through PROBECTL_ALERT_WEBHOOK_CA_FILE.
type receiptPKI struct {
	ca     *crypto.CA
	caFile string
}

func newReceiptPKI(t *testing.T) *receiptPKI {
	t.Helper()
	ca, err := crypto.GenerateCA("probectl-f18-receipt-ca", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "receipt-ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &receiptPKI{ca: ca, caFile: caFile}
}

func (p *receiptPKI) serverTLS(t *testing.T, host string) *tls.Config {
	t.Helper()
	certPEM, keyPEM, err := p.ca.IssueServerCert(host, []string{host}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}
