// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package tenantkeys_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestShippedVaultCompatibleKeysRevokeAndRecoverWithinTenant(t *testing.T) {
	base := strings.TrimRight(os.Getenv("PROBECTL_TEST_OPENBAO_URL"), "/")
	if base == "" && os.Getenv("PROBECTL_TEST_REQUIRE_OPENBAO") != "1" {
		t.Skip("set the owned OpenBao TLS fixture to run the live key-revocation receipt")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "openbao") ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		t.Fatal("the owned OpenBao endpoint must be a loopback or isolated lab HTTPS origin")
	}
	ca := os.Getenv("PROBECTL_TEST_OPENBAO_CA_FILE")
	role := os.Getenv("PROBECTL_TEST_OPENBAO_ROLE_ID")
	secret := os.Getenv("PROBECTL_TEST_OPENBAO_SECRET_ID")
	admin := os.Getenv("PROBECTL_TEST_OPENBAO_ADMIN_TOKEN")
	if ca == "" || role == "" || secret == "" || admin == "" {
		t.Fatal("the OpenBao fixture requires trusted TLS, AppRole and a separate provisioning credential")
	}
	t.Setenv("PROBECTL_TEST_OPENBAO_ADMIN_TOKEN", "")
	client, err := crypto.HardenedHTTPClientWithCAFile(5*time.Second, ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	vault := openBaoTestVault{base: base, admin: admin, client: client}
	stack := shipped.Start(t, shipped.Options{Name: "openbaokeys", TenantBand: 3, Env: map[string]string{
		"PROBECTL_BYOK_REF_PREFIX":         "vault:secret/probectl/byok/{tenant}/",
		"PROBECTL_SECRETS_VAULT_ADDR":      base,
		"PROBECTL_SECRETS_VAULT_ROLE_ID":   role,
		"PROBECTL_SECRETS_VAULT_SECRET_ID": secret,
		"PROBECTL_SECRETS_VAULT_TOKEN":     "",
		"SSL_CERT_FILE":                    ca,
	}})
	operator := stack.OnboardOperator(t, "root@msp-openbao-receipt.example")
	stamp := fmt.Sprint(time.Now().UnixNano())
	type vaultLane struct {
		tenant, cookie, token, ref, path, material string
		managed, sealed                            string
	}
	var lanes [2]vaultLane
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		slug := fmt.Sprintf("openbao-%s-%d", stamp, i)
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		lane.tenant = tenant.ID
		lane.cookie = stack.SignIn(t, tenant.ID, email, slug)
		lane.token = stack.APIToken(t, lane.cookie, "security.keys", "tenant.read")
		lane.managed = createShippedVaultRule(t, stack, lane.cookie, "before-rotation-"+slug, randomKey(t))
		lane.ref, lane.path, lane.material = vault.seed(t, tenant.ID)
	}
	healthStatus, deploymentHealth := stack.Do(t, lanes[1].cookie, http.MethodGet, "/v1/secrets/health", nil)
	if healthStatus != http.StatusOK {
		t.Fatal("the sibling could not read the deployment health", healthStatus)
	}
	for i := range lanes {
		lane, sibling := &lanes[i], &lanes[1-i]
		credentials := map[string]string{"PROBECTL_API_TOKEN": lane.token}
		_, reason, code := stack.CLI(credentials, "key", "rotate", "--body", byokBody(sibling.ref))
		if code == 0 || !strings.Contains(reason, "byok_ref is not an allowed secret reference for this tenant") {
			t.Fatal("the other tenant's valid reference was not refused")
		}
		var rotation struct{ Version int }
		stack.MustCLI(t, credentials, &rotation, "key", "rotate", "--body", byokBody(lane.ref))
		var chain struct{ Items []keyVersion }
		stack.MustCLI(t, credentials, &chain, "key", "list")
		if rotation.Version != 2 || modeState(chain.Items, 2) != "byok/active" {
			t.Fatal("the current owner did not activate its real OpenBao key")
		}
		lane.sealed = createShippedVaultRule(t, stack, lane.cookie, fmt.Sprintf("after-rotation-%s-%d", stamp, i), randomKey(t))
	}
	owner, sibling := lanes[0], lanes[1]
	vault.call(t, http.MethodDelete, "/v1/secret/data/"+owner.path, nil)
	if code, _ := stack.Do(t, owner.cookie, http.MethodGet, "/v1/alerts/"+owner.sealed, nil); code == http.StatusOK {
		t.Fatal("the removed OpenBao key still opened the owner's sealed value")
	}
	if code, _ := stack.Do(t, owner.cookie, http.MethodPost, "/v1/alerts", shippedVaultRule("owner-revoked-"+stamp, randomKey(t))); code == http.StatusCreated {
		t.Fatal("the removed OpenBao key still sealed new records")
	}
	for _, rule := range []struct{ cookie, id string }{{owner.cookie, owner.managed}, {sibling.cookie, sibling.managed}, {sibling.cookie, sibling.sealed}} {
		if code, _ := stack.Do(t, rule.cookie, http.MethodGet, "/v1/alerts/"+rule.id, nil); code != http.StatusOK {
			t.Fatal("removing one external key affected an independent key or tenant", code)
		}
	}
	if status, got := stack.Do(t, sibling.cookie, http.MethodGet, "/v1/secrets/health", nil); status != http.StatusOK || !bytes.Equal(got, deploymentHealth) {
		t.Fatal("tenant-owned OpenBao activity changed the shared deployment health", status)
	}
	vault.put(t, owner.path, owner.material)
	if code, _ := stack.Do(t, owner.cookie, http.MethodGet, "/v1/alerts/"+owner.sealed, nil); code != http.StatusOK {
		t.Fatal("the owner's exact restored key did not reopen the original record", code)
	}
	created := createShippedVaultRule(t, stack, owner.cookie, "owner-recovered-"+stamp, randomKey(t))
	if code, _ := stack.Do(t, owner.cookie, http.MethodGet, "/v1/alerts/"+created, nil); code != http.StatusOK {
		t.Fatal("the owner's restored key did not open the new record", code)
	}
	status, raw := stack.Do(t, owner.cookie, http.MethodGet, "/v1/secrets/health", nil)
	var health struct {
		ResolverRunning bool `json:"resolver_running"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &health) != nil || !health.ResolverRunning ||
		bytes.Contains(raw, []byte(owner.material)) || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("the authenticated health view did not report a running redacted resolver", status)
	}

	// Use a separate disposable key for the permanent deletion proof. Only
	// its reference enters the independently copied Postgres state.
	shredPath := "probectl/byok/" + owner.tenant + "/copied-data-key"
	vault.put(t, shredPath, randomKey(t))
	var rotation struct{ Version int }
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": owner.token}, &rotation,
		"key", "rotate", "--body", byokBody("vault:secret/"+shredPath+"#key"))
	if rotation.Version != 3 {
		t.Fatal("the separate copy-proof key did not activate")
	}
	backedRule := createShippedVaultRule(t, stack, owner.cookie, "copied-before-key-deletion-"+stamp, randomKey(t))
	originalCiphertext := backedAlertCiphertext(t, stack.AdminDSN, owner.tenant, backedRule)
	if !strings.HasPrefix(originalCiphertext, "tk1:") {
		t.Fatal("the original rule was not sealed under a tenant key")
	}

	restoredDSN := stack.RestartControlOnPostgresCopy(t, "control-restored-key-copy")
	if code, _ := stack.Do(t, owner.cookie, http.MethodGet, "/v1/alerts/"+backedRule, nil); code != http.StatusOK {
		t.Fatal("the independent copy could not open before key destruction", code)
	}
	if got := backedAlertCiphertext(t, restoredDSN, owner.tenant, backedRule); got != originalCiphertext {
		t.Fatal("the copied ciphertext differs from the source")
	}
	vault.call(t, http.MethodDelete, "/v1/secret/metadata/"+shredPath, nil)
	if code := vault.request(t, http.MethodGet, "/v1/secret/metadata/"+shredPath, nil); code != http.StatusNotFound {
		t.Fatalf("the deleted key still has version metadata (HTTP %d)", code)
	}
	stack.RestartControl(t, "control-restored-key-destroyed", nil)
	if code, _ := stack.Do(t, owner.cookie, http.MethodGet, "/v1/alerts/"+backedRule, nil); code != http.StatusInternalServerError {
		t.Fatal("the original scoped record did not fail closed after permanent key deletion", code)
	}
	if got := backedAlertCiphertext(t, restoredDSN, owner.tenant, backedRule); got != originalCiphertext {
		t.Fatal("the copied row changed during external key destruction")
	}
	if code, _ := stack.Do(t, sibling.cookie, http.MethodGet, "/v1/alerts/"+sibling.sealed, nil); code != http.StatusOK {
		t.Fatal("the sibling could not open its independent external-key record on the copy", code)
	}
}

func backedAlertCiphertext(t *testing.T, dsn, tenant, rule string) string {
	t.Helper()
	db, err := store.Open(t.Context(), dsn, 1, 0, 5*time.Second)
	if err != nil {
		t.Fatal("open the owned ciphertext fixture", err)
	}
	defer db.Close()
	return (&keysStack{db: db}).storedSecret(t, tenant, rule)
}

func shippedVaultRule(name, secret string) map[string]any {
	return map[string]any{
		"name": name, "metric": "probectl_probe_loss_ratio", "type": "threshold",
		"comparison": "gt", "threshold": 0.5, "severity": "critical",
		"channels": []map[string]any{{"type": "webhook", "url": "https://hooks.invalid", "secret": secret}},
	}
}

func createShippedVaultRule(t *testing.T, stack *shipped.Stack, cookie, name, secret string) string {
	t.Helper()
	code, raw := stack.Do(t, cookie, http.MethodPost, "/v1/alerts", shippedVaultRule(name, secret))
	var rule struct {
		ID       string
		Channels []struct{ Secret string }
	}
	if code != http.StatusCreated || json.Unmarshal(raw, &rule) != nil || rule.ID == "" ||
		len(rule.Channels) != 1 || rule.Channels[0].Secret != "***" {
		t.Fatal("the alert rule was not stored with a redacted channel", code)
	}
	return rule.ID
}

type openBaoTestVault struct {
	base, admin string
	client      *http.Client
}

func (v openBaoTestVault) seed(t *testing.T, tenant string) (ref, path, material string) {
	t.Helper()
	path = "probectl/byok/" + tenant + "/live-key"
	material = randomKey(t)
	v.put(t, path, material)
	t.Cleanup(func() { v.call(t, http.MethodDelete, "/v1/secret/metadata/"+path, nil) })
	return "vault:secret/" + path + "#key", path, material
}

func (v openBaoTestVault) put(t *testing.T, path, material string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"data": map[string]string{"key": material}})
	if err != nil {
		t.Fatal(err)
	}
	v.call(t, http.MethodPost, "/v1/secret/data/"+path, body)
}

func (v openBaoTestVault) call(t *testing.T, method, path string, body []byte) {
	t.Helper()
	if code := v.request(t, method, path, body); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("owned OpenBao provisioning returned HTTP %d", code)
	}
}

func (v openBaoTestVault) request(t *testing.T, method, path string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(method, v.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", v.admin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}
