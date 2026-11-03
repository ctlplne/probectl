// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Uses real TLS, bearer-token/role authentication, consent, policy/call/domain
// audits and pooled storage. This is not the final release/telemetry receipt.
func TestTagMCPMetadataMutationsUseRealTenantAuthorizationAndAtomicAudit(t *testing.T) {
	core, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	a, b := freshTenant(t, db, "mcp-tags-a"), freshTenant(t, db, "mcp-tags-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove MCP tag tenants: %v", err)
		}
	})
	routingContext, foreignContext, entityID := gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
	for _, tenant := range []string{a, b} {
		if _, err := db.Pool().Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`,
			tenant, routingContext, gouuid.NewString(), gouuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool().Exec(ctx, `INSERT INTO entities (tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','same-edge')`, tenant, routingContext, entityID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool().Exec(ctx, `INSERT INTO tenant_governance (tenant_id,ai_remote_egress)
			VALUES ($1,true) ON CONFLICT (tenant_id) DO UPDATE SET ai_remote_egress=true`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Pool().Exec(ctx, `INSERT INTO entity_contexts
		(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'foreign','foreign')`,
		b, foreignContext, gouuid.NewString(), gouuid.NewString()); err != nil {
		t.Fatal(err)
	}
	type identity struct{ tenant, user, email, role, token string }
	makeIdentity := func(tenant string) identity {
		t.Helper()
		id := identity{tenant: tenant, email: "writer@" + tenant + ".example.test"}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, id.email, "MCP tag writer")
			if err != nil {
				return err
			}
			id.user = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "tag-writer", "Tag writer", "MCP metadata proof")
			if err != nil {
				return err
			}
			id.role = role.ID
			for _, permission := range []string{permTagsRead, permTagsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, id.role, permission); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", id.user, id.role)
		}); err != nil {
			t.Fatal(err)
		}
		var err error
		id.token, err = auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(ctx, tenant, id.user, "tag-writer", crypto.Hash([]byte(id.token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, second := makeIdentity(a), makeIdentity(b)
	cfg := &config.Config{}
	server := NewMCPServerWithPolicyLoader(cfg, core.log, db.Pool(), pathstore.NewMemory(), 0,
		NewAIEgressGate(cfg, core.log, db.Pool()), nil, nil, core.MCPPolicyLoader(), AISources{NativeFlow: core})
	socket := httptest.NewTLSServer(server.HTTPHandler(NewMCPAuthenticator(db.Pool(), NewTenantStatusCache(db.Pool(), 0), false)))
	t.Cleanup(socket.Close)
	const wire = "2026-07-28"
	request := func(id identity, method, tool string, args any, wantOK bool) json.RawMessage {
		t.Helper()
		params := map[string]any{"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    wire,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}}
		if method == "tools/call" {
			params["name"], params["arguments"] = tool, args
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, socket.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+id.token)
		req.Header.Set("MCP-Protocol-Version", wire)
		req.Header.Set("Mcp-Method", method)
		if tool != "" {
			req.Header.Set("Mcp-Name", tool)
		}
		// Credential scope must win over the other tenant's untrusted hint.
		hint := b
		if id.tenant == b {
			hint = a
		}
		req.Header.Set("X-Probectl-Tenant", hint)
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if err != nil || len(raw) > 2<<20 {
			t.Fatal("MCP metadata response exceeded bounded wire budget")
		}
		if !wantOK && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
			return nil
		}
		if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
			var final []byte
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				if bytes.HasPrefix(line, []byte("data: ")) {
					final = bytes.TrimPrefix(line, []byte("data: "))
				}
			}
			raw = final
		}
		var reply struct {
			Error  json.RawMessage `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(raw, &reply) != nil {
			t.Fatalf("MCP metadata returned non-JSON: status %d", response.StatusCode)
		}
		if method == "tools/list" {
			if response.StatusCode != http.StatusOK || len(reply.Error) != 0 {
				t.Fatal("MCP tools/list failed")
			}
			return reply.Result
		}
		var result struct {
			IsError bool            `json:"isError"`
			Data    json.RawMessage `json:"structuredContent"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if len(reply.Result) > 0 && json.Unmarshal(reply.Result, &result) != nil {
			t.Fatal("invalid MCP tool result")
		}
		ok := response.StatusCode == http.StatusOK && len(reply.Error) == 0 && !result.IsError && len(result.Data) > 0 && string(result.Data) != "null"
		if ok != wantOK {
			t.Fatalf("MCP %s success=%v expected %v: %.400s", tool, ok, wantOK, raw)
		}
		if !ok {
			if len(result.Data) > 0 && string(result.Data) != "null" {
				t.Fatal("refused metadata call exposed structured data")
			}
			return nil
		}
		if len(result.Content) != 1 || !bytes.Equal(bytes.TrimSpace([]byte(result.Content[0].Text)), bytes.TrimSpace(result.Data)) {
			t.Fatal("MCP metadata text and structured results disagree")
		}
		return result.Data
	}
	writes := map[string]int{}
	call := func(id identity, tool string, args map[string]any, wantOK bool) map[string]json.RawMessage {
		t.Helper()
		raw := request(id, "tools/call", tool, args, wantOK)
		if !wantOK {
			return nil
		}
		writes[id.tenant]++
		var out map[string]json.RawMessage
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid typed MCP metadata result")
		}
		return out
	}
	resultID := func(result map[string]json.RawMessage) string {
		t.Helper()
		var id string
		if json.Unmarshal(result["id"], &id) != nil || gouuid.Validate(id) != nil {
			t.Fatal("metadata mutation omitted its owned UUID")
		}
		return id
	}
	for _, id := range []identity{first, second} {
		var list struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if json.Unmarshal(request(id, "tools/list", "", nil, true), &list) != nil {
			t.Fatal("invalid tool list")
		}
		names := map[string]bool{}
		for _, tool := range list.Tools {
			names[tool.Name] = true
		}
		for _, name := range []string{"tag_definition_write", "tag_rule_write", "tag_assignment_write"} {
			if !names[name] {
				t.Fatalf("required MCP metadata mutation is unavailable: %s", name)
			}
		}
	}
	ruleInput := func(tagID, value string) map[string]any {
		return map[string]any{"tag_id": tagID, "target_kind": "device", "match_kind": "snmp_field",
			"snmp_field": "sys_descr", "snmp_value": " OS\r\n\tv1 ", "value": value, "priority": 7}
	}
	assignmentInput := func(tagID, value string) map[string]any {
		return map[string]any{"tag_id": tagID, "target_kind": "device", "target_id": entityID, "value": value}
	}
	type lane struct {
		identity
		definition, rule, assignment string
	}
	lanes := []lane{{identity: first}, {identity: second}}
	for i := range lanes {
		l := &lanes[i]
		l.definition = resultID(call(l.identity, "tag_definition_write", map[string]any{"action": "create", "input": map[string]any{"key": "customer"}}, true))
		l.rule = resultID(call(l.identity, "tag_rule_write", map[string]any{"action": "create", "context_id": routingContext, "input": ruleInput(l.definition, "initial")}, true))
		l.assignment = resultID(call(l.identity, "tag_assignment_write", map[string]any{"action": "create", "context_id": routingContext, "input": assignmentInput(l.definition, "initial")}, true))
		for _, side := range []string{"agent", "test", "prefix"} {
			call(l.identity, "tag_rule_write", map[string]any{"action": "update", "context_id": routingContext,
				"id": l.rule, "input": map[string]any{"tag_id": l.definition, "target_kind": side,
					"match_kind": "cidr", "address_side": side, "cidr": "10.42.0.0/16", "value": "canonical"}}, true)
		}
	}
	// Same context/entity IDs and tag keys do not make another tenant's IDs usable.
	for i, l := range lanes {
		other := lanes[1-i]
		call(l.identity, "tag_definition_write", map[string]any{"action": "update", "id": other.definition, "input": map[string]any{"key": "stolen"}}, false)
		call(l.identity, "tag_definition_write", map[string]any{"action": "delete", "id": other.definition, "confirmed": true}, false)
		for _, family := range []struct {
			tool, id string
			input    map[string]any
		}{
			{"tag_rule_write", other.rule, ruleInput(l.definition, "stolen")},
			{"tag_assignment_write", other.assignment, assignmentInput(l.definition, "stolen")},
		} {
			call(l.identity, family.tool, map[string]any{"action": "update", "context_id": routingContext, "id": family.id, "input": family.input}, false)
			call(l.identity, family.tool, map[string]any{"action": "delete", "context_id": routingContext, "id": family.id, "confirmed": true}, false)
		}
		call(l.identity, "tag_rule_write", map[string]any{"action": "create", "context_id": routingContext, "input": ruleInput(other.definition, "foreign")}, false)
		call(l.identity, "tag_assignment_write", map[string]any{"action": "create", "context_id": routingContext, "input": assignmentInput(other.definition, "foreign")}, false)
	}
	call(first, "tag_rule_write", map[string]any{"action": "create", "context_id": foreignContext, "input": ruleInput(lanes[0].definition, "foreign")}, false)
	// A real stored context policy denies one tenant but not the identical context
	// ID in the other tenant. The framework's tenant-wide precheck is insufficient.
	var policyID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny metadata context", Enabled: true,
			Effect: auth.PolicyDeny, Permission: permTagsWrite, Resource: map[string]string{"context_id": routingContext}, Priority: 100})
		if err == nil {
			policyID = policy.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	core.abac.invalidate(a)
	call(first, "tag_rule_write", map[string]any{"action": "update", "context_id": routingContext, "id": lanes[0].rule, "input": ruleInput(lanes[0].definition, "denied")}, false)
	call(first, "tag_assignment_write", map[string]any{"action": "delete", "context_id": routingContext, "id": lanes[0].assignment, "confirmed": true}, false)
	call(second, "tag_rule_write", map[string]any{"action": "update", "context_id": routingContext, "id": lanes[1].rule, "input": ruleInput(lanes[1].definition, "allowed")}, true)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
	}); err != nil {
		t.Fatal(err)
	}
	core.abac.invalidate(a)
	// Imported provenance is not writable through the manual family.
	importedID := gouuid.NewString()
	if _, err := db.Pool().Exec(ctx, `INSERT INTO tenant_tag_assignments
		(tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,value,source,source_ref,reviewed_at)
		VALUES ($1,$2,$3,$4,'device',$5,'device','imported','netbox','reviewed-1',clock_timestamp())`, a, routingContext, importedID, lanes[0].definition, entityID); err != nil {
		t.Fatal(err)
	}
	call(first, "tag_assignment_write", map[string]any{"action": "update", "context_id": routingContext, "id": importedID, "input": assignmentInput(lanes[0].definition, "forged")}, false)
	call(first, "tag_assignment_write", map[string]any{"action": "delete", "context_id": routingContext, "id": importedID, "confirmed": true}, false)
	for _, l := range lanes {
		call(l.identity, "tag_definition_write", map[string]any{"action": "update", "id": l.definition, "input": map[string]any{"key": "customer_renamed"}}, true)
		call(l.identity, "tag_rule_write", map[string]any{"action": "update", "context_id": routingContext, "id": l.rule, "input": ruleInput(l.definition, "updated")}, true)
		call(l.identity, "tag_assignment_write", map[string]any{"action": "update", "context_id": routingContext, "id": l.assignment, "input": assignmentInput(l.definition, "updated")}, true)
		var key, ruleValue, snmpValue, assignmentValue string
		if err := db.Pool().QueryRow(ctx, `SELECT d.key,r.value,r.snmp_value,m.value FROM tenant_tag_definitions d
			JOIN tenant_tag_rules r ON r.tenant_id=d.tenant_id AND r.tag_id=d.id
			JOIN tenant_tag_assignments m ON m.tenant_id=d.tenant_id AND m.tag_id=d.id AND m.source='manual'
			WHERE d.tenant_id=$1 AND d.id=$2 AND r.id=$3 AND m.id=$4`, l.tenant, l.definition, l.rule, l.assignment).
			Scan(&key, &ruleValue, &snmpValue, &assignmentValue); err != nil {
			t.Fatal(err)
		}
		if key != "customer_renamed" || ruleValue != "updated" || assignmentValue != "updated" || snmpValue != " OS\r\n\tv1 " {
			t.Fatal("MCP metadata write changed another scope or lost exact SNMP text")
		}
		call(l.identity, "tag_rule_write", map[string]any{"action": "delete", "context_id": routingContext, "id": l.rule, "confirmed": true}, true)
		call(l.identity, "tag_assignment_write", map[string]any{"action": "delete", "context_id": routingContext, "id": l.assignment, "confirmed": true}, true)
		call(l.identity, "tag_definition_write", map[string]any{"action": "delete", "id": l.definition, "confirmed": true}, true)
		var remaining, audits int
		if err := db.Pool().QueryRow(ctx, `SELECT
			(SELECT count(*) FROM tenant_tag_definitions WHERE tenant_id=$1)+
			(SELECT count(*) FROM tenant_tag_rules WHERE tenant_id=$1)+
			(SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=$1),
			(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action LIKE 'tag.%')`, l.tenant).Scan(&remaining, &audits); err != nil {
			t.Fatal(err)
		}
		if remaining != 0 || audits != writes[l.tenant] {
			t.Fatalf("tenant metadata/audit mismatch: remaining=%d audits=%d successful=%d", remaining, audits, writes[l.tenant])
		}
	}
	// Domain audit failure must roll back both the data and its revision. The
	// trigger is scoped to this owned tenant and tag events; MCP call audits work.
	var before, after int64
	if err := db.Pool().QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1`, a).Scan(&before); err != nil {
		t.Fatal(err)
	}
	fault := "probectl_qa_beta_tag_audit_" + strings.ReplaceAll(gouuid.NewString(), "-", "")
	if _, err := db.Pool().Exec(ctx, `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.tenant_id='`+a+`'::uuid AND NEW.action LIKE 'tag.%' THEN RAISE EXCEPTION 'QA tag audit refused'; END IF;
		RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		if _, err := db.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`()`); err != nil {
			t.Errorf("remove owned audit fault: %v", err)
		}
	}
	t.Cleanup(dropFault)
	call(first, "tag_definition_write", map[string]any{"action": "create", "input": map[string]any{"key": "must_rollback"}}, false)
	var leaked int
	if err := db.Pool().QueryRow(ctx, `SELECT revision,(SELECT count(*) FROM tenant_tag_definitions WHERE tenant_id=$1) FROM tenant_tag_revisions WHERE tenant_id=$1`, a).Scan(&after, &leaked); err != nil {
		t.Fatal(err)
	}
	if before != after || leaked != 0 {
		t.Fatal("audit refusal committed metadata or its revision")
	}
	dropFault()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return (store.RoleBindings{}).Unbind(ctx, sc, "user", first.user, first.role)
	}); err != nil {
		t.Fatal(err)
	}
	call(first, "tag_definition_write", map[string]any{"action": "create", "input": map[string]any{"key": "revoked"}}, false)
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM tenant_tag_definitions WHERE tenant_id=$1`, a).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("revoked role wrote metadata")
	}
}
