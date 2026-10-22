// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package alert_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The alerting signal: the probe-success gauge every test result writes to
// Prometheus (1 ok, 0 failed), and the rule every tenant here defines on it.
const (
	alertMetric    = "probectl_probe_success"
	evalInterval   = 2 * time.Second
	relayUser      = "probectl-relay"
	relayPassword  = "relay-word-pass-for-the-receipt"
	alertMailFrom  = "probectl-alerts@msp.example"
	deliveryWithin = 90 * time.Second
)

// TestAlertingRealStack is the real-stack receipt for alerting (F8): rules a
// tenant defines through the rendered Alerts page, the public API and the
// CLI are evaluated by the shipped control plane against real probe results
// in Prometheus, fire when the tenant's own target goes down, resolve when it
// comes back, and are delivered to that tenant's own receivers only: a
// signed webhook through the deployment's egress proxy and an email through
// an authenticated, STARTTLS-secured relay. Firing state is read back
// through GET /v1/alerts/active, `probectl alert active` and the rendered
// /alerts page, each holding only the caller's own alerts.
//
// The stack is the shipped control plane and agent on the four-store profile
// (shipped.Start): PostgreSQL behind the least-privilege serve login, Kafka
// with strict tenant lanes, ClickHouse, Prometheus (the evaluator's metric
// source), TLS everywhere, Dex as the IdP (production session auth), an MSP
// license and a test-bundle signing key. Tenant A is pooled, tenant B hybrid.
// Delivery is configured the way an MSP deploys it: HTTPS_PROXY names an
// egress proxy on loopback (DPR-289), the webhook receivers and the relay sit
// behind the receipt's own CA (PROBECTL_ALERT_WEBHOOK_CA_FILE and
// PROBECTL_ALERT_SMTP_CA_FILE, DPR-290), and the relay requires AUTH. Each
// tenant's webhook names a public hostname; the proxy is the only thing that
// knows where it lives, as a real egress proxy resolves it.
//
//  1. Each tenant's agent runs a TCP test against the tenant's own loopback
//     target, and Prometheus holds probectl_probe_success = 1 for it.
//  2. Rules, all "probectl_probe_success < 1, critical", with no label match:
//     each watches every probe of its own tenant, so only the tenant pin
//     keeps the other tenant's probes out. A creates a webhook rule in the
//     rendered "Create alert rule" dialog and an email rule through
//     POST /v1/alerts; B creates one rule with both channels through
//     `probectl alert create`, after the same command refuses a webhook on
//     127.0.0.1 (SSRF guard). Rules read back per tenant through the API and
//     the CLI with secrets redacted, are sealed at rest, and another
//     tenant's rule is not found.
//  3. Every rule evaluates to "normal" on the real series.
//  4. A's target goes down: both of A's rules fire and deliver to A's
//     receiver and A's mailbox; B's receiver and mailbox stay empty. The
//     active alerts (API, CLI, console) show A its two alerts and B none.
//  5. A recovers and B's target goes down: A's resolutions and B's firing
//     alert are delivered, each to its own tenant; the active views follow.
//  6. B recovers: B's resolutions are delivered.
//  7. Every delivery is checked: the webhook body is probectl.alert.v1 for
//     the tenant's rule and series, its signature verifies with the tenant's
//     own secret and not the other's, and no secret travels in it. Every
//     mail went TLS-secured and authenticated to the tenant's own recipient
//     only. The proxy tunneled only the two receivers' names. Each rule's
//     evaluation ledger (API, and the CLI for B) holds normal, firing and
//     resolved. No secret reaches the control plane's log.
func TestAlertingRealStack(t *testing.T) {
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	pki := newReceiptPKI(t)
	A := &alertTenant{slug: "alert-acme-" + run, name: "Alert Acme", model: "pooled", admin: "ada@acme.example",
		hookHost: "hooks.acme-alerts.example", mail: "oncall@acme.example", secret: "acme-hook-signing-word-" + run}
	B := &alertTenant{slug: "alert-globex-" + run, name: "Alert Globex", model: "hybrid", admin: "bob@globex.example",
		hookHost: "hooks.globex-alerts.example", mail: "noc@globex.example", secret: "globex-hook-signing-word-" + run}
	tenants := []*alertTenant{A, B}
	routes := map[string]string{}
	for _, tn := range tenants {
		tn.receiver = startHookReceiver(t, pki, tn.hookHost)
		routes[net.JoinHostPort(tn.hookHost, "443")] = tn.receiver.addr
	}
	proxy := startEgressProxy(t, routes)
	relay := testsupport.StartSMTPServer(t, pki.serverTLS(t, "localhost"), relayUser, relayPassword)
	_, relayPort, _ := net.SplitHostPort(relay.Addr)

	st := shipped.Start(t, shipped.Options{Name: "alerting", TenantBand: 4, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
		"PROBECTL_ALERT_EVAL_INTERVAL":       evalInterval.String(),
		"HTTPS_PROXY":                        "http://" + proxy.addr,
		"NO_PROXY":                           "localhost,127.0.0.1",
		"PROBECTL_ALERT_WEBHOOK_CA_FILE":     pki.caFile,
		"PROBECTL_ALERT_SMTP_ADDR":           "localhost:" + relayPort,
		"PROBECTL_ALERT_SMTP_FROM":           alertMailFrom,
		"PROBECTL_ALERT_SMTP_TLS_MODE":       "starttls",
		"PROBECTL_ALERT_SMTP_USERNAME":       relayUser,
		"PROBECTL_ALERT_SMTP_PASSWORD":       relayPassword,
		"PROBECTL_ALERT_SMTP_CA_FILE":        pki.caFile,
	}})
	op := st.OnboardOperator(t, "root@msp-alerting.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}

	// 1. Tenants, agents and the real signal.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("alert%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "alert.read", "alert.write",
			"test.read", "test.write", "test.allow_private", "agent.read")
		tn.target = newFlapTarget(t)
		tn.agent = uuid.NewString()
		tn.agentName = "alert-agent-" + tn.id[:8]
		identity := st.EnrollAgent(t, tn.id, tn.agent, tn.agentName)
		st.StartAgent(t, identity, tn.agentName, []string{"tcp"}, `test_sync:
  enabled: true
  interval: 2s
  allowed_types: [tcp]
  allow_private_targets: true
`)
	}
	for _, tn := range tenants {
		tn.testID = tn.createTCPTest(t, st)
	}
	for _, tn := range tenants {
		shipped.Await(t, "probectl_probe_success = 1 for "+tn.slug+"'s TCP test", 120*time.Second, func() bool {
			v, ok := promValue(t, fmt.Sprintf(`max(%s{tenant_id=%q,test_id=%q})`, alertMetric, tn.id, tn.testID))
			return ok && v == 1
		})
	}

	// 2. Rules through the console, the API and the CLI.
	A.hookRule = alertRuleRef{Name: "probe down (webhook) " + A.mark}
	A.hookRule.ID = A.createRuleInConsole(t, st)
	A.mailRule = alertRuleRef{Name: "probe down (email) " + A.mark}
	A.mailRule.ID = A.createRuleAPI(t, st, A.mailRule.Name, []map[string]any{{"type": "email", "recipients": []string{A.mail}}})
	B.refusesPrivateWebhook(t, st)
	B.hookRule = alertRuleRef{Name: "probe down " + B.mark}
	B.hookRule.ID = B.createRuleCLI(t, st, B.hookRule.Name, []map[string]any{
		{"type": "webhook", "url": B.hookURL(), "secret": B.secret},
		{"type": "email", "recipients": []string{B.mail}},
	})
	B.mailRule = B.hookRule // one rule carries both of B's channels
	A.rules = []alertRuleRef{A.hookRule, A.mailRule}
	B.rules = []alertRuleRef{B.hookRule}
	for _, tn := range tenants {
		tn.checkRules(t, st, tn.other(A, B))
	}
	checkSecretsSealed(t, st, A.secret, B.secret)

	// 3. Every rule evaluates to normal on the real series.
	for _, tn := range tenants {
		for _, r := range tn.rules {
			shipped.Await(t, tn.slug+"'s rule "+r.Name+" evaluating to normal", 60*time.Second, func() bool {
				return tn.hasEvaluation(t, st, r.ID, "normal")
			})
		}
	}
	if n := len(A.receiver.all()) + len(B.receiver.all()) + len(relay.Messages()); n != 0 {
		t.Fatalf("%d deliveries before any target went down: webhooks %s, mail to %v",
			n, deliverySummary(A, B), mailRecipients(relay))
	}

	// 4. A's target goes down.
	A.target.down(t)
	awaitHook(t, A, "firing", A.hookRule.ID, tenants)
	awaitMail(t, relay, A.mail, A.mailRule.Name, "firing")
	time.Sleep(4 * evalInterval) // several more passes in which B must stay quiet
	if got := B.receiver.all(); len(got) != 0 {
		t.Errorf("B's receiver got %d deliveries while only A's target was down: %s", len(got), deliverySummary(B))
	}
	for _, m := range relay.Messages() {
		if containsAny(m.To, B.mail) {
			t.Errorf("B's mailbox got mail while only A's target was down: %q", m.Data)
		}
	}
	A.checkActive(t, st, A.rules, B)
	B.checkActive(t, st, nil, A)
	A.renderAlerts(t, st, A.rules, B, false)
	B.renderAlerts(t, st, nil, A, false)

	// 5. A recovers; B's target goes down.
	A.target.up(t)
	B.target.down(t)
	awaitHook(t, A, "resolved", A.hookRule.ID, tenants)
	awaitMail(t, relay, A.mail, A.mailRule.Name, "resolved")
	awaitHook(t, B, "firing", B.hookRule.ID, tenants)
	awaitMail(t, relay, B.mail, B.mailRule.Name, "firing")
	shipped.Await(t, "A's active alerts clearing", 30*time.Second, func() bool { return len(A.active(t, st)) == 0 })
	B.checkActive(t, st, B.rules, A)
	A.checkActive(t, st, nil, B)
	B.renderAlerts(t, st, B.rules, A, true)
	A.renderAlerts(t, st, nil, B, false)

	// 6. B recovers.
	B.target.up(t)
	awaitHook(t, B, "resolved", B.hookRule.ID, tenants)
	awaitMail(t, relay, B.mail, B.mailRule.Name, "resolved")
	shipped.Await(t, "B's active alerts clearing", 30*time.Second, func() bool { return len(B.active(t, st)) == 0 })

	// 7. What every receiver got, and what never left.
	for _, tn := range tenants {
		tn.checkDeliveries(t, tn.other(A, B))
		for _, r := range tn.rules {
			for _, state := range []string{"normal", "firing", "resolved"} {
				if !tn.hasEvaluation(t, st, r.ID, state) {
					t.Errorf("%s's rule %s has no %q evaluation receipt", tn.slug, r.Name, state)
				}
			}
		}
	}
	var cliEvals struct {
		Items []evaluation `json:"items"`
	}
	st.MustCLI(t, B.env(), &cliEvals, "alert", "evaluations", B.hookRule.ID)
	if states := evalStates(cliEvals.Items); !strings.Contains(states, "firing") || !strings.Contains(states, "resolved") {
		t.Errorf("probectl alert evaluations %s as %s = %s, want firing and resolved", B.hookRule.ID, B.slug, states)
	}
	checkMail(t, relay, A, B)
	logEvidence(t, relay, proxy, A, B)
	if hosts := proxy.tunneled(); fmt.Sprint(hosts) != fmt.Sprint(sortedHosts(A.hookHost, B.hookHost)) {
		t.Errorf("the egress proxy tunneled to %v, want exactly the two receivers %v", hosts, sortedHosts(A.hookHost, B.hookHost))
	}
	if refused := proxy.refusedTargets(); len(refused) != 0 {
		t.Errorf("the egress proxy was asked for unknown destinations: %v", refused)
	}
	logRaw, err := os.ReadFile(st.Log)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{A.secret, B.secret, relayPassword} {
		if strings.Contains(string(logRaw), secret) {
			t.Errorf("the control plane's log holds a delivery secret (%d chars)", len(secret))
		}
	}
}

type alertRuleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type alertTenant struct {
	slug, name, model, admin string
	hookHost, mail, secret   string
	id, mark, cookie, token  string
	agent, agentName, testID string
	target                   *flapTarget
	receiver                 *hookReceiver
	hookRule, mailRule       alertRuleRef
	rules                    []alertRuleRef
}

func (tn *alertTenant) other(a, b *alertTenant) *alertTenant {
	if tn == a {
		return b
	}
	return a
}

func (tn *alertTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *alertTenant) hookURL() string { return "https://" + tn.hookHost + "/probectl/alerts" }

func (tn *alertTenant) get(t *testing.T, st *shipped.Stack, path string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, path, nil)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.300s", path, tn.slug, code, raw)
	}
}

func (tn *alertTenant) ownsRule(id string) bool {
	for _, r := range tn.rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// createTCPTest defines the tenant's TCP test to its own loopback target with
// the audited private-target override.
func (tn *alertTenant) createTCPTest(t *testing.T, st *shipped.Stack) string {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": "tcp " + tn.mark, "type": "tcp", "target": tn.target.addr, "interval_seconds": 10,
		"timeout_seconds": 3, "enabled": true, "params": map[string]string{"allow_private_targets": "true"},
	})
	var test struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
		t.Fatalf("POST /v1/tests as %s = %d: %s", tn.slug, code, raw)
	}
	return test.ID
}

func ruleBody(name string, channels []map[string]any) map[string]any {
	return map[string]any{
		"name": name, "metric": alertMetric, "type": "threshold", "comparison": "lt", "threshold": 1,
		"for_n": 1, "renotify_seconds": 0, "severity": "critical", "channels": channels,
	}
}

// createRuleInConsole creates the tenant's webhook rule in the rendered
// "Create alert rule" dialog.
func (tn *alertTenant) createRuleInConsole(t *testing.T, st *shipped.Stack) string {
	t.Helper()
	field := func(label string) string { return `[role=dialog] label:text-is("` + label + `") + div input` }
	choice := func(label string) string { return `[role=dialog] label:text-is("` + label + `") + div select` }
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/alerts",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Alerts", "No alert rules"},
		Steps: []testsupport.RenderStep{
			{Click: "Create rule", Expect: []string{"Create alert rule"}},
			{Fill: field("Name"), Value: tn.hookRule.Name},
			{Fill: field("Metric"), Value: alertMetric},
			{Select: choice("Comparison"), Value: "lt"},
			{Fill: field("Threshold"), Value: "1"},
			{Select: choice("Severity"), Value: "critical"},
			{Select: choice("Delivery channel"), Value: "webhook"},
			{Fill: field("Webhook URL"), Value: tn.hookURL()},
			{Fill: field("Webhook secret"), Value: tn.secret},
			{Click: "Create rule", Within: "[role=dialog]", Expect: []string{"Rule created", tn.hookRule.Name, "webhook (signed)"}},
		},
	})
	return tn.findRule(t, st, tn.hookRule.Name)
}

func (tn *alertTenant) createRuleAPI(t *testing.T, st *shipped.Stack, name string, channels []map[string]any) string {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/alerts", ruleBody(name, channels))
	var rule alertRuleRef
	if code != http.StatusCreated || json.Unmarshal(raw, &rule) != nil || rule.ID == "" {
		t.Fatalf("POST /v1/alerts (%s) as %s = %d: %s", name, tn.slug, code, raw)
	}
	return rule.ID
}

func (tn *alertTenant) createRuleCLI(t *testing.T, st *shipped.Stack, name string, channels []map[string]any) string {
	t.Helper()
	var rule alertRuleRef
	st.MustCLI(t, tn.env(), &rule, "alert", "create", "--body-file", st.SecretFile(t, ruleBody(name, channels)))
	if rule.ID == "" {
		t.Fatalf("probectl alert create (%s) as %s returned no id", name, tn.slug)
	}
	return rule.ID
}

// refusesPrivateWebhook: a webhook on a loopback address is refused when the
// rule is saved, before anything is stored (the SSRF guard, AUTHZ-16).
func (tn *alertTenant) refusesPrivateWebhook(t *testing.T, st *shipped.Stack) {
	t.Helper()
	body := ruleBody("private hook "+tn.mark, []map[string]any{{"type": "webhook", "url": "https://" + tn.receiver.addr + "/probectl/alerts"}})
	out, errOut, code := st.CLI(tn.env(), "alert", "create", "--body-file", st.SecretFile(t, body))
	if code == 0 || !strings.Contains(out+errOut, "public, non-internal host") {
		t.Errorf("probectl alert create with a webhook on %s as %s = exit %d: %.300s%.300s, want the SSRF refusal",
			tn.receiver.addr, tn.slug, code, errOut, out)
	}
}

func (tn *alertTenant) findRule(t *testing.T, st *shipped.Stack, name string) string {
	t.Helper()
	var rules struct{ Items []alertRuleRef }
	tn.get(t, st, "/v1/alerts", &rules)
	for _, r := range rules.Items {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("tenant %s has no rule named %q after the console created it: %+v", tn.slug, name, rules.Items)
	return ""
}

type ruleView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Channels []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	} `json:"channels"`
}

// checkRules reads the tenant's rules through the API and the CLI: exactly its
// own, webhook secrets redacted, and the other tenant's rule not found.
func (tn *alertTenant) checkRules(t *testing.T, st *shipped.Stack, other *alertTenant) {
	t.Helper()
	var api struct {
		Items          []ruleView `json:"items"`
		AlertingActive bool       `json:"alerting_active"`
	}
	tn.get(t, st, "/v1/alerts", &api)
	if !api.AlertingActive {
		t.Errorf("GET /v1/alerts as %s says alerting is inactive", tn.slug)
	}
	var cli struct {
		Items []ruleView `json:"items"`
	}
	st.MustCLI(t, tn.env(), &cli, "alert", "list")
	for surface, items := range map[string][]ruleView{"GET /v1/alerts": api.Items, "probectl alert list": cli.Items} {
		ids := map[string]bool{}
		for _, r := range items {
			ids[r.ID] = true
			if r.TenantID != tn.id {
				t.Errorf("%s as %s holds rule %s of tenant %s", surface, tn.slug, r.ID, r.TenantID)
			}
			for _, ch := range r.Channels {
				if ch.Type == "webhook" && ch.Secret != "***" {
					t.Errorf("%s as %s returns webhook secret %q, want it redacted", surface, tn.slug, ch.Secret)
				}
			}
		}
		if len(items) != len(tn.rules) {
			t.Errorf("%s as %s lists %d rules, want exactly its %d", surface, tn.slug, len(items), len(tn.rules))
		}
		for _, r := range tn.rules {
			if !ids[r.ID] {
				t.Errorf("%s as %s lacks its rule %s", surface, tn.slug, r.Name)
			}
		}
	}
	foreign := other.rules[0].ID
	for _, path := range []string{"/v1/alerts/" + foreign, "/v1/alerts/" + foreign + "/evaluations"} {
		if code, raw := st.Do(t, tn.cookie, http.MethodGet, path, nil); code != http.StatusNotFound {
			t.Errorf("GET %s (%s's rule) as %s = %d, want 404: %.200s", path, other.slug, tn.slug, code, raw)
		}
	}
	if out, _, code := st.CLI(tn.env(), "alert", "get", foreign); code == 0 {
		t.Errorf("probectl alert get %s (%s's rule) as %s succeeded: %.200s", foreign, other.slug, tn.slug, out)
	}
}

// checkSecretsSealed: the webhook secrets are sealed at rest, never stored in
// the clear.
func checkSecretsSealed(t *testing.T, st *shipped.Stack, secrets ...string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var all string
	if err := pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(channels::text, ' '), '') FROM alert_rules`).Scan(&all); err != nil {
		t.Fatalf("read alert_rules: %v", err)
	}
	if !strings.Contains(all, "webhook") {
		t.Fatalf("alert_rules holds no webhook channel: %.300s", all)
	}
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Errorf("alert_rules stores a webhook secret in the clear (%d chars)", len(s))
		}
	}
}

type evaluation struct {
	State  string            `json:"state"`
	RuleID string            `json:"rule_id"`
	Labels map[string]string `json:"labels"`
}

func evalStates(items []evaluation) string {
	states := make([]string, 0, len(items))
	for _, it := range items {
		states = append(states, it.State)
	}
	return strings.Join(states, ",")
}

func (tn *alertTenant) hasEvaluation(t *testing.T, st *shipped.Stack, ruleID, state string) bool {
	t.Helper()
	var out struct {
		Items            []evaluation `json:"items"`
		EvaluatorRunning bool         `json:"evaluator_running"`
	}
	tn.get(t, st, "/v1/alerts/"+ruleID+"/evaluations?limit=100", &out)
	for _, e := range out.Items {
		if e.RuleID != ruleID {
			t.Fatalf("%s's evaluations of %s hold a receipt of rule %s", tn.slug, ruleID, e.RuleID)
		}
		if e.Labels["tenant_id"] != "" && e.Labels["tenant_id"] != tn.id {
			t.Fatalf("%s's evaluations of %s hold tenant %s's series", tn.slug, ruleID, e.Labels["tenant_id"])
		}
		if e.State == state {
			return true
		}
	}
	return false
}

type activeAlert struct {
	Fingerprint string            `json:"fingerprint"`
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	Severity    string            `json:"severity"`
	Metric      string            `json:"metric"`
	Labels      map[string]string `json:"labels"`
	Value       float64           `json:"value"`
}

func (tn *alertTenant) active(t *testing.T, st *shipped.Stack) []activeAlert {
	t.Helper()
	var out struct {
		Items            []activeAlert `json:"items"`
		EvaluatorRunning bool          `json:"evaluator_running"`
	}
	tn.get(t, st, "/v1/alerts/active", &out)
	if !out.EvaluatorRunning {
		t.Fatalf("GET /v1/alerts/active as %s says the evaluator is not running", tn.slug)
	}
	return out.Items
}

// checkActive: the API and the CLI show the tenant exactly its own firing
// rules on its own series, and nothing of the other tenant's.
func (tn *alertTenant) checkActive(t *testing.T, st *shipped.Stack, want []alertRuleRef, other *alertTenant) {
	t.Helper()
	var cli struct {
		Items []activeAlert `json:"items"`
	}
	st.MustCLI(t, tn.env(), &cli, "alert", "active")
	for surface, items := range map[string][]activeAlert{"GET /v1/alerts/active": tn.active(t, st), "probectl alert active": cli.Items} {
		got := map[string]bool{}
		for _, a := range items {
			got[a.RuleID] = true
			if !tn.ownsRule(a.RuleID) || a.Labels["tenant_id"] != tn.id || a.Labels["test_id"] != tn.testID ||
				a.Metric != alertMetric || a.Severity != "critical" || a.Value != 0 {
				t.Errorf("%s as %s holds %+v, want only its own rules firing on its own test %s with value 0", surface, tn.slug, a, tn.testID)
			}
			if other.ownsRule(a.RuleID) || a.Labels["tenant_id"] == other.id {
				t.Errorf("%s as %s holds %s's alert %+v", surface, tn.slug, other.slug, a)
			}
		}
		if len(items) != len(want) {
			t.Errorf("%s as %s lists %d active alerts, want %d: %+v", surface, tn.slug, len(items), len(want), items)
		}
		for _, r := range want {
			if !got[r.ID] {
				t.Errorf("%s as %s lacks its firing rule %s", surface, tn.slug, r.Name)
			}
		}
	}
}

// renderAlerts renders /alerts as the tenant's admin: its own firing alerts
// (or "No active alerts") and rules, never the other tenant's.
func (tn *alertTenant) renderAlerts(t *testing.T, st *shipped.Stack, firing []alertRuleRef, other *alertTenant, details bool) {
	t.Helper()
	spec := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/alerts",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Active alerts", "Alert rules"},
		Absent: []string{other.id, other.testID, other.mark},
	}
	for _, r := range tn.rules {
		spec.Expect = append(spec.Expect, r.Name)
	}
	if len(firing) == 0 {
		spec.Expect = append(spec.Expect, "No active alerts")
	} else {
		// The console leaves tenant_id out of the series (the tenant indicator
		// is always visible), so the series is the tenant's own test and agent.
		spec.Expect = append(spec.Expect, "critical", "test_id="+tn.testID, "agent_id="+tn.agent)
		spec.Absent = append(spec.Absent, "No active alerts")
	}
	if details {
		spec.Steps = []testsupport.RenderStep{{Click: "Details", Expect: []string{firing[0].Name, "firing", alertMetric}}}
	}
	testsupport.RenderUI(t, spec)
}

// --- delivery checks ---

func awaitHook(t *testing.T, tn *alertTenant, state, ruleID string, everyone []*alertTenant) {
	t.Helper()
	deadline := time.Now().Add(deliveryWithin)
	for {
		for _, d := range tn.receiver.all() {
			if d.Payload.State == state && d.Payload.Rule.ID == ruleID {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for a %s webhook for %s's rule at its receiver; every receiver got %s",
				deliveryWithin, state, tn.slug, deliverySummary(everyone...))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func awaitMail(t *testing.T, relay *testsupport.SMTPServer, to, ruleName, state string) {
	t.Helper()
	shipped.Await(t, fmt.Sprintf("a %s mail for %q to %s", state, ruleName, to), deliveryWithin, func() bool {
		for _, m := range relay.Messages() {
			if containsAny(m.To, to) && strings.Contains(m.Data, ruleName) && strings.Contains(m.Data, "is "+state+".") {
				return true
			}
		}
		return false
	})
}

// checkDeliveries: the tenant's receiver got exactly one firing and one
// resolved delivery of its webhook rule, each its own tenant's alert on its
// own series, signed with its own secret, carrying no secret.
func (tn *alertTenant) checkDeliveries(t *testing.T, other *alertTenant) {
	t.Helper()
	got := tn.receiver.all()
	var states []string
	for _, d := range got {
		states = append(states, d.Payload.State)
		p := d.Payload
		if p.Version != "probectl.alert.v1" || p.TenantID != tn.id || p.Rule.ID != tn.hookRule.ID ||
			p.Rule.Name != tn.hookRule.Name || p.Labels["tenant_id"] != tn.id || p.Labels["test_id"] != tn.testID ||
			p.Metric != alertMetric || p.Severity != "critical" || p.Comparison != "lt" || p.Threshold != 1 {
			t.Errorf("%s's receiver got %+v, want its own rule %s on its own test %s", tn.slug, p, tn.hookRule.ID, tn.testID)
		}
		if p.TenantID == other.id || p.Labels["tenant_id"] == other.id || other.ownsRule(p.Rule.ID) {
			t.Errorf("%s's receiver got %s's alert: %+v", tn.slug, other.slug, p)
		}
		if want := "sha256=" + hex.EncodeToString(crypto.Sign([]byte(tn.secret), d.Body)); d.Signature != want {
			t.Errorf("%s's delivery signature %q does not verify with its own secret", tn.slug, d.Signature)
		}
		if d.Signature == "sha256="+hex.EncodeToString(crypto.Sign([]byte(other.secret), d.Body)) {
			t.Errorf("%s's delivery is signed with %s's secret", tn.slug, other.slug)
		}
		for _, s := range []string{tn.secret, other.secret, relayPassword} {
			if strings.Contains(string(d.Body), s) {
				t.Errorf("%s's webhook body carries a secret", tn.slug)
			}
		}
		if d.Path != "/probectl/alerts" || d.ContentType != "application/json" || d.UserAgent != "probectl-alerting" {
			t.Errorf("%s's delivery = %s %s %s, want POST /probectl/alerts application/json from probectl-alerting", tn.slug, d.Path, d.ContentType, d.UserAgent)
		}
	}
	if strings.Join(states, ",") != "firing,resolved" {
		t.Errorf("%s's receiver got states %v, want exactly firing then resolved", tn.slug, states)
	}
}

// checkMail: every mail went TLS-secured and authenticated, from the
// configured sender, to its own tenant's recipient only, about its own rule;
// four in all (each tenant's rule firing and resolving).
func checkMail(t *testing.T, relay *testsupport.SMTPServer, a, b *alertTenant) {
	t.Helper()
	msgs := relay.Messages()
	if len(msgs) != 4 {
		t.Errorf("the relay accepted %d mails, want 4 (each tenant's email rule firing and resolving)", len(msgs))
	}
	for _, m := range msgs {
		if !m.TLS || m.User != relayUser || m.From != alertMailFrom || len(m.To) != 1 {
			t.Errorf("mail %+v was not TLS-secured, authenticated, from %s to one recipient", m, alertMailFrom)
		}
		for _, pair := range [][2]*alertTenant{{a, b}, {b, a}} {
			own, other := pair[0], pair[1]
			if !containsAny(m.To, own.mail) {
				continue
			}
			if !strings.Contains(m.Data, own.mailRule.Name) || strings.Contains(m.Data, other.mark) ||
				!strings.Contains(m.Data, "[probectl][critical]") || !strings.Contains(m.Data, "Metric: "+alertMetric) {
				t.Errorf("%s's mail is not about its own rule only: %q", own.slug, m.Data)
			}
		}
		for _, s := range []string{a.secret, b.secret, relayPassword} {
			if strings.Contains(m.Data, s) {
				t.Errorf("a mail carries a secret: %q", m.Data)
			}
		}
	}
	if refused := relay.Refused(); len(refused) != 0 {
		t.Errorf("the relay refused %v (plaintext or unauthenticated mail)", refused)
	}
}

// logEvidence records what each receiver got, for the receipt's report.
func logEvidence(t *testing.T, relay *testsupport.SMTPServer, proxy *egressProxy, tenants ...*alertTenant) {
	t.Helper()
	for _, tn := range tenants {
		for _, d := range tn.receiver.all() {
			t.Logf("webhook %s <- %s rule=%s tenant=%s series{tenant_id=%s test_id=%s} value=%g signature verified with %s's secret",
				tn.hookHost, d.Payload.State, d.Payload.Rule.ID, d.Payload.TenantID, d.Payload.Labels["tenant_id"],
				d.Payload.Labels["test_id"], d.Payload.Value, tn.slug)
		}
	}
	for _, m := range relay.Messages() {
		subject := ""
		for _, line := range strings.Split(m.Data, "\n") {
			if strings.HasPrefix(line, "Subject: ") {
				subject = strings.TrimPrefix(line, "Subject: ")
			}
		}
		t.Logf("mail %s -> %v tls=%t auth=%s subject=%q", m.From, m.To, m.TLS, m.User, subject)
	}
	t.Logf("egress proxy tunnels: %d to %v", proxy.tunnels.Load(), proxy.tunneled())
}

// deliverySummary names, per receiver, each delivery's state, payload tenant
// and series tenant.
func deliverySummary(tenants ...*alertTenant) string {
	var parts []string
	for _, tn := range tenants {
		for _, d := range tn.receiver.all() {
			parts = append(parts, fmt.Sprintf("%s<-%s(tenant %s, series of tenant %s)",
				tn.hookHost, d.Payload.State, d.Payload.TenantID, d.Payload.Labels["tenant_id"]))
		}
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

func mailRecipients(relay *testsupport.SMTPServer) []string {
	var out []string
	for _, m := range relay.Messages() {
		out = append(out, strings.Join(m.To, ","))
	}
	return out
}

func containsAny(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func sortedHosts(hosts ...string) []string {
	out := append([]string(nil), hosts...)
	sort.Strings(out)
	return out
}

// --- the receipt's network: targets, receivers, proxy, PKI ---

// flapTarget is a loopback TCP service a test probes, which the receipt takes
// down (closes) and brings back on the same port.
type flapTarget struct {
	addr string
	mu   sync.Mutex
	ln   net.Listener
}

func newFlapTarget(t *testing.T) *flapTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &flapTarget{addr: ln.Addr().String()}
	f.serve(ln)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.ln != nil {
			_ = f.ln.Close()
		}
	})
	return f
}

func (f *flapTarget) serve(ln net.Listener) {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

func (f *flapTarget) down(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
}

func (f *flapTarget) up(t *testing.T) {
	t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", f.addr); err == nil {
			f.serve(ln)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("bring the target back on %s: %v", f.addr, err)
}

type hookPayload struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Rule    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rule"`
	TenantID   string            `json:"tenant_id"`
	Severity   string            `json:"severity"`
	Metric     string            `json:"metric"`
	Labels     map[string]string `json:"labels"`
	Value      float64           `json:"value"`
	Threshold  float64           `json:"threshold"`
	Comparison string            `json:"comparison"`
	Reason     string            `json:"reason"`
	FiredAt    string            `json:"fired_at"`
}

type hookDelivery struct {
	Path, Signature, ContentType, UserAgent string
	Body                                    []byte
	Payload                                 hookPayload
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
		d := hookDelivery{Path: r.URL.Path, Signature: r.Header.Get("X-Probectl-Signature"),
			ContentType: r.Header.Get("Content-Type"), UserAgent: r.Header.Get("User-Agent"), Body: body}
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
	addr    string
	mu      sync.Mutex
	hosts   map[string]bool
	refused []string
	tunnels atomic.Int64
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
		p.mu.Lock()
		p.refused = append(p.refused, req.Method+" "+req.Host)
		p.mu.Unlock()
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
	p.tunnels.Add(1)
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

func (p *egressProxy) refusedTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.refused...)
}

// receiptPKI is the receipt's own CA: the receivers' and the relay's
// certificates, trusted by the control plane through its CA-file keys.
type receiptPKI struct {
	ca     *crypto.CA
	caFile string
}

func newReceiptPKI(t *testing.T) *receiptPKI {
	t.Helper()
	ca, err := crypto.GenerateCA("probectl-f8-receipt-ca", 2*time.Hour)
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

// promValue runs one instant query against the dev stack's Prometheus.
func promValue(t *testing.T, query string) (float64, bool) {
	t.Helper()
	resp, err := http.Get(strings.TrimRight(os.Getenv("PROBECTL_PROM_URL"), "/") + "/api/v1/query?query=" + url.QueryEscape(query))
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || len(out.Data.Result) == 0 {
		return 0, false
	}
	s, _ := out.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}
