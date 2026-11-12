// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// An operator can author a source only in the authenticated tenant and one
// routing context. A foreign anchor, another context for the same agent, or a
// principal missing agent.write cannot create a canonical write path.
func TestEntityAdminAssignmentIsTenantAndContextBound(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "entity-admin-a"), freshTenant(t, db, "entity-admin-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove entity admin fixtures: %v", err)
		}
	})
	site, vrf := "West DC", "Customer A"
	createdContexts := map[string]entity.ContextRecord{}
	createContext := func(tenant string) string {
		t.Helper()
		rec := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": site, "vrf_label": vrf})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create context %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		var got entity.ContextRecord
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil ||
			got.TenantID != tenant || got.ContextID == "" || got.SiteID == "" || got.VRFID == "" ||
			got.SiteLabel != site || got.VRFLabel != vrf {
			t.Fatalf("context %s: %+v %v", tenant, got, err)
		}
		createdContexts[tenant] = got
		return got.ContextID
	}
	ctxA, ctxB := createContext(a), createContext(b)
	if ctxA == ctxB || createdContexts[a].SiteID == createdContexts[b].SiteID ||
		createdContexts[a].VRFID == createdContexts[b].VRFID {
		t.Fatal("two tenants received one site, VRF or routing-context identity")
	}
	duplicate := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", a,
		map[string]string{"site_label": site, "vrf_label": vrf})
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate named context was not refused: %d %s",
			duplicate.Code, duplicate.Body.String())
	}
	for _, fixture := range []struct{ tenant, context string }{{a, ctxA}, {b, ctxB}} {
		rec := apiReq(t, h, http.MethodGet, "/v1/entity-contexts?limit=1", fixture.tenant, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list tenant contexts %s: %d %s", fixture.tenant, rec.Code, rec.Body.String())
		}
		var page entity.ContextPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 1 ||
			page.Items[0].TenantID != fixture.tenant || page.Items[0].ContextID != fixture.context {
			t.Fatalf("tenant context page %s: %+v %v", fixture.tenant, page, err)
		}
	}
	createDevice := func(tenant, routingContext string) string {
		t.Helper()
		rec := apiReq(t, h, http.MethodPost, "/v1/entities", tenant,
			map[string]string{"context_id": routingContext, "kind": "device", "label": "router"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create device %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		var got entity.Record
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.ID == "" ||
			got.Scope.TenantID != tenant || got.Scope.ContextID != routingContext {
			t.Fatalf("device %s: %+v %v", tenant, got, err)
		}
		return got.ID
	}
	deviceA, deviceB := createDevice(a, ctxA), createDevice(b, ctxB)
	agentA, agentB := uuid(t), uuid(t)
	for _, fixture := range []struct{ tenant, agent string }{{a, agentA}, {b, agentB}} {
		err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(fixture.tenant)),
			db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (store.Agents{}).Register(ctx, sc, fixture.agent,
					"entity-agent-"+fixture.agent, "fixture", "", crypto.AgentSPIFFEID(fixture.tenant, fixture.agent),
					[]string{"collector", "device"})
				return err
			})
		if err != nil {
			t.Fatalf("seed agent %s: %v", fixture.tenant, err)
		}
	}
	assignment := func(agent, routingContext, anchor string) map[string]string {
		return map[string]string{"agent_id": agent, "source_kind": "device_target",
			"source_ref": "10.42.0.1", "context_id": routingContext,
			"anchor_entity_id": anchor}
	}
	if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", a,
		assignment(agentA, ctxA, deviceB)); rec.Code != http.StatusConflict && rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign tenant anchor accepted: %d %s", rec.Code, rec.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", a,
		assignment(agentA, ctxB, "")); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign context accepted: %d %s", rec.Code, rec.Body.String())
	}
	for _, fixture := range []struct{ tenant, agent, routingContext, anchor string }{
		{a, agentA, ctxA, deviceA}, {b, agentB, ctxB, deviceB},
	} {
		rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", fixture.tenant,
			assignment(fixture.agent, fixture.routingContext, fixture.anchor))
		if rec.Code != http.StatusOK {
			t.Fatalf("own source assignment %s: %d %s", fixture.tenant, rec.Code, rec.Body.String())
		}
	}
	secondContext := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", a,
		map[string]string{"site_label": site, "vrf_label": "Customer B"})
	if secondContext.Code != http.StatusCreated {
		t.Fatalf("second context: %d %s", secondContext.Code, secondContext.Body.String())
	}
	var next entity.ContextRecord
	if err := json.Unmarshal(secondContext.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.SiteID != createdContexts[a].SiteID || next.VRFID == createdContexts[a].VRFID ||
		next.SiteLabel != site || next.VRFLabel != "Customer B" {
		t.Fatalf("named site was not reused with a distinct VRF: %+v", next)
	}
	first := apiReq(t, h, http.MethodGet, "/v1/entity-contexts?limit=1", a, nil)
	var firstPage entity.ContextPage
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &firstPage) != nil ||
		len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first context page: %d %s", first.Code, first.Body.String())
	}
	second := apiReq(t, h, http.MethodGet,
		"/v1/entity-contexts?limit=1&cursor="+firstPage.NextCursor, a, nil)
	var secondPage entity.ContextPage
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &secondPage) != nil ||
		len(secondPage.Items) != 1 || secondPage.NextCursor != "" ||
		secondPage.Items[0].ContextID == firstPage.Items[0].ContextID {
		t.Fatalf("second context page: %d %s", second.Code, second.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", a,
		assignment(agentA, next.ContextID, "")); rec.Code != http.StatusConflict {
		t.Fatalf("one agent entered two contexts: %d %s", rec.Code, rec.Body.String())
	}
	denied := httptest.NewRequest(http.MethodPut, "/v1/entity-source-contexts", nil)
	denied.Header.Set("X-Probectl-Tenant", a)
	denied.Header.Set(testWithholdPermissionsHeader, "agent.write")
	deniedResult := httptest.NewRecorder()
	h.ServeHTTP(deniedResult, denied)
	if deniedResult.Code != http.StatusForbidden {
		t.Fatalf("role without agent.write entered admin route: %d", deniedResult.Code)
	}
	deniedList := httptest.NewRequest(http.MethodGet, "/v1/entity-contexts", nil)
	deniedList.Header.Set("X-Probectl-Tenant", a)
	deniedList.Header.Set(testWithholdPermissionsHeader, "entities.read")
	deniedListResult := httptest.NewRecorder()
	h.ServeHTTP(deniedListResult, deniedList)
	if deniedListResult.Code != http.StatusForbidden {
		t.Fatalf("role without entities.read listed contexts: %d", deniedListResult.Code)
	}
	for _, fixture := range []struct{ tenant, agent, routingContext, anchor string }{
		{a, agentA, ctxA, deviceA}, {b, agentB, ctxB, deviceB},
	} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(fixture.tenant))
		got, err := store.NewEntityRegistry(db.Pool()).ResolveSourceContext(ctx, fixture.tenant,
			entity.SourceKey{AgentID: fixture.agent, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"})
		if err != nil || got.ContextID != fixture.routingContext {
			t.Fatalf("source context %s: %+v %v", fixture.tenant, got, err)
		}
		err = tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var anchor string
			if err := sc.Q.QueryRow(ctx, `SELECT anchor_entity_id::text FROM entity_source_contexts
				WHERE tenant_id=$1 AND agent_id=$2 AND source_ref='10.42.0.1'`,
				fixture.tenant, fixture.agent).Scan(&anchor); err != nil {
				return err
			}
			if anchor != fixture.anchor {
				t.Fatalf("tenant %s anchor=%s, want %s", fixture.tenant, anchor, fixture.anchor)
			}
			var audited int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events
				WHERE tenant_id=$1 AND action='entity.source.assigned'`,
				fixture.tenant).Scan(&audited); err != nil {
				return err
			}
			if audited != 1 {
				t.Fatalf("tenant %s source audit count=%d, want 1", fixture.tenant, audited)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("anchor read %s: %v", fixture.tenant, err)
		}
	}
	// MCP has its own output path: prove that it cannot return the SNMP claim
	// without metrics.read, and that a tenant-A caller cannot use tenant B's
	// context even while holding the source-assignment permission.
	entitySerial := strings.ReplaceAll(uuid(t), "-", "")
	if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), a, agentA,
		crypto.EntitySPIFFEID(a, agentA), entitySerial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("seed MCP evidence identity: %v", err)
	}
	if accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(context.Background(), tenancy.ID(a)), store.NewEntityRegistry(db.Pool()), agentA, entitySerial,
		[]entity.Observation{{ID: uuid(t), Source: entity.SourceKey{
			AgentID: agentA, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"},
			Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
			SourceRef: "snmp:router", ObservedAt: time.Now()}}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("seed MCP source evidence: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	blueSerial := strings.ReplaceAll(uuid(t), "-", "")
	if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), b, agentB,
		crypto.EntitySPIFFEID(b, agentB), blueSerial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("seed blue evidence identity: %v", err)
	}
	if accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(context.Background(), tenancy.ID(b)), store.NewEntityRegistry(db.Pool()), agentB, blueSerial,
		[]entity.Observation{{ID: uuid(t), Source: entity.SourceKey{
			AgentID: agentB, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"},
			Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
			SourceRef: "snmp:blue-router", ObservedAt: time.Now()}}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("seed blue evidence: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	for _, fixture := range []struct{ tenant, context, id, source string }{
		{a, ctxA, deviceA, "snmp:router"},
		{b, ctxB, deviceB, "snmp:blue-router"},
	} {
		url := "/v1/entities/" + fixture.id + "/evidence?context_id=" + fixture.context + "&limit=1"
		got := apiReq(t, h, http.MethodGet, url, fixture.tenant, nil)
		var page entity.EvidencePage
		if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &page) != nil ||
			len(page.Items) != 1 || page.Scope.TenantID != fixture.tenant ||
			page.Items[0].SourceRef != fixture.source || !page.Items[0].Current {
			t.Fatalf("scoped evidence page %s: %d %s", fixture.tenant, got.Code, got.Body.String())
		}
		foreign := apiReq(t, h, http.MethodGet,
			"/v1/entities/"+fixture.id+"/evidence?context_id="+next.ContextID,
			fixture.tenant, nil)
		if foreign.Code != http.StatusNotFound {
			t.Fatalf("evidence crossed routing context %s: %d %s", fixture.tenant, foreign.Code, foreign.Body.String())
		}
	}
	denySource := httptest.NewRequest(http.MethodGet,
		"/v1/entities/"+deviceA+"/evidence?context_id="+ctxA, nil)
	denySource.Header.Set("X-Probectl-Tenant", a)
	denySource.Header.Set(testWithholdPermissionsHeader, "metrics.read")
	deniedEvidence := httptest.NewRecorder()
	h.ServeHTTP(deniedEvidence, denySource)
	if deniedEvidence.Code != http.StatusForbidden {
		t.Fatalf("source-limited evidence read: %d %s", deniedEvidence.Code, deniedEvidence.Body.String())
	}
	peerDevice := createDevice(a, ctxA)
	var redEvidenceID string
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM entity_evidence
				WHERE tenant_id=$1 AND context_id=$2 AND entity_id=$3`,
				a, ctxA, deviceA).Scan(&redEvidenceID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_links
				(tenant_id,context_id,id,from_entity_id,to_entity_id,evidence_id,kind,observed_at)
				VALUES ($1,$2,$3,$4,$5,$6,'physical',statement_timestamp())`,
				a, ctxA, uuid(t), deviceA, peerDevice, redEvidenceID)
			return err
		}); err != nil {
		t.Fatalf("seed evidence-backed link: %v", err)
	}
	redLinks := apiReq(t, h, http.MethodGet,
		"/v1/entities/"+deviceA+"/links?context_id="+ctxA+"&limit=1", a, nil)
	var linkPage entity.LinkPage
	if redLinks.Code != http.StatusOK || json.Unmarshal(redLinks.Body.Bytes(), &linkPage) != nil ||
		len(linkPage.Items) != 1 || linkPage.Items[0].ToEntityID != peerDevice ||
		linkPage.Items[0].EvidenceID != redEvidenceID {
		t.Fatalf("scoped link page: %d %s", redLinks.Code, redLinks.Body.String())
	}
	blueLinks := apiReq(t, h, http.MethodGet,
		"/v1/entities/"+deviceB+"/links?context_id="+ctxB, b, nil)
	var blueLinkPage entity.LinkPage
	if blueLinks.Code != http.StatusOK || json.Unmarshal(blueLinks.Body.Bytes(), &blueLinkPage) != nil ||
		len(blueLinkPage.Items) != 0 {
		t.Fatalf("tenant A link leaked to B: %d %s", blueLinks.Code, blueLinks.Body.String())
	}
	denyLink := httptest.NewRequest(http.MethodGet,
		"/v1/entities/"+deviceA+"/links?context_id="+ctxA, nil)
	denyLink.Header.Set("X-Probectl-Tenant", a)
	denyLink.Header.Set(testWithholdPermissionsHeader, "metrics.read")
	deniedLink := httptest.NewRecorder()
	h.ServeHTTP(deniedLink, denyLink)
	if deniedLink.Code != http.StatusForbidden {
		t.Fatalf("source-limited link read: %d %s", deniedLink.Code, deniedLink.Body.String())
	}
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	mcpServer := NewMCPServerWithPolicyLoader(&config.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), db.Pool(), nil, 0, gate,
		nil, nil, func(context.Context, string) ([]auth.Policy, error) { return nil, nil })
	reader := &auth.Principal{TenantID: a, UserID: "entity-reader",
		Permissions: map[string]bool{"entities.read": true}}
	for _, fixture := range []struct{ tenant, ownContext, ownDevice, foreignContext, foreignDevice string }{
		{a, ctxA, deviceA, ctxB, deviceB},
		{b, ctxB, deviceB, ctxA, deviceA},
	} {
		principal := &auth.Principal{TenantID: fixture.tenant, UserID: "entity-reader",
			Permissions: map[string]bool{"entities.read": true}}
		listData, failed := nativeControlCall(t, mcpServer, principal, "entity_list",
			mcp.EntityListInput{ContextID: fixture.ownContext, Limit: 100})
		var listed mcp.EntityListResult
		if failed || json.Unmarshal(listData, &listed) != nil {
			t.Fatalf("MCP entity list %s: %s", fixture.tenant, listData)
		}
		foundOwn := false
		for _, item := range listed.Items {
			if item.ID == fixture.foreignDevice {
				t.Fatalf("MCP entity list crossed tenant %s: %s", fixture.tenant, listData)
			}
			foundOwn = foundOwn || item.ID == fixture.ownDevice
		}
		if !foundOwn {
			t.Fatalf("MCP entity list omitted own device %s: %s", fixture.tenant, listData)
		}
		getData, failed := nativeControlCall(t, mcpServer, principal, "entity_get",
			mcp.EntityGetInput{ContextID: fixture.ownContext, ID: fixture.ownDevice})
		var got mcp.EntityItemResult
		if failed || json.Unmarshal(getData, &got) != nil || got.ID != fixture.ownDevice {
			t.Fatalf("MCP entity get %s: %s", fixture.tenant, getData)
		}
		if _, failed := nativeControlCall(t, mcpServer, principal, "entity_list",
			mcp.EntityListInput{ContextID: fixture.foreignContext}); !failed {
			t.Fatalf("MCP entity list accepted foreign context for %s", fixture.tenant)
		}
		if _, failed := nativeControlCall(t, mcpServer, principal, "entity_get",
			mcp.EntityGetInput{ContextID: fixture.foreignContext, ID: fixture.foreignDevice}); !failed {
			t.Fatalf("MCP entity get accepted foreign device for %s", fixture.tenant)
		}
	}
	contextData, failed := nativeControlCall(t, mcpServer, reader, "entity_context_list",
		mcp.EntityContextListInput{Limit: 100})
	if failed {
		t.Fatalf("MCP context list failed: %s", contextData)
	}
	var contextList mcp.EntityContextListResult
	if err := json.Unmarshal(contextData, &contextList); err != nil || len(contextList.Items) != 2 {
		t.Fatalf("MCP tenant A context list: %+v %v", contextList, err)
	}
	for _, item := range contextList.Items {
		if item.ContextID == ctxB {
			t.Fatal("MCP tenant A saw tenant B context")
		}
	}
	args := mcp.EntityResolveInput{ContextID: ctxA, Kind: "address", Value: "10.42.0.1"}
	if _, failed := nativeControlCall(t, mcpServer, reader, "entity_resolve", args); !failed {
		t.Fatal("MCP source-limited reader saw SNMP evidence")
	}
	detailArgs := mcp.EntityDetailListInput{ContextID: ctxA, ID: deviceA, Limit: 1}
	if _, failed := nativeControlCall(t, mcpServer, reader, "entity_evidence_list", detailArgs); !failed {
		t.Fatal("MCP source-limited reader saw entity evidence")
	}
	if _, failed := nativeControlCall(t, mcpServer, reader, "entity_link_list", detailArgs); !failed {
		t.Fatal("MCP source-limited reader saw evidence-backed link")
	}
	reader.Permissions["metrics.read"] = true
	evidenceData, failed := nativeControlCall(t, mcpServer, reader, "entity_evidence_list", detailArgs)
	var mcpEvidence mcp.EntityEvidenceListResult
	if failed || json.Unmarshal(evidenceData, &mcpEvidence) != nil || len(mcpEvidence.Items) != 1 ||
		mcpEvidence.Items[0].SourceRef != "snmp:router" {
		t.Fatalf("MCP authorized evidence: %s", evidenceData)
	}
	linkData, failed := nativeControlCall(t, mcpServer, reader, "entity_link_list", detailArgs)
	var mcpLinks mcp.EntityLinkListResult
	if failed || json.Unmarshal(linkData, &mcpLinks) != nil || len(mcpLinks.Items) != 1 ||
		mcpLinks.Items[0].EvidenceID != redEvidenceID {
		t.Fatalf("MCP authorized link: %s", linkData)
	}
	if _, failed := nativeControlCall(t, mcpServer, reader, "entity_evidence_list",
		mcp.EntityDetailListInput{ContextID: ctxB, ID: deviceB}); !failed {
		t.Fatal("MCP tenant A read tenant B evidence")
	}
	data, failed := nativeControlCall(t, mcpServer, reader, "entity_resolve", args)
	if failed || !json.Valid(data) {
		t.Fatalf("MCP authorized resolution failed: %s", data)
	}
	var resolution mcp.EntityResolutionResult
	if err := json.Unmarshal(data, &resolution); err != nil || resolution.EntityID != deviceA || resolution.Status != "resolved" {
		t.Fatalf("MCP scoped resolution: %+v %v", resolution, err)
	}
	operator := &auth.Principal{TenantID: a, UserID: "entity-operator",
		Permissions: map[string]bool{"agent.write": true}}
	createdContextData, failed := nativeControlCall(t, mcpServer, operator,
		"entity_context_create", mcp.EntityContextCreateInput{SiteLabel: site, VRFLabel: "Customer C"})
	if failed {
		t.Fatalf("MCP context create failed: %s", createdContextData)
	}
	var createdContext mcp.EntityContextResult
	if err := json.Unmarshal(createdContextData, &createdContext); err != nil || createdContext.ContextID == "" {
		t.Fatalf("MCP context create result: %+v %v", createdContext, err)
	}
	createdEntityData, failed := nativeControlCall(t, mcpServer, operator, "entity_create",
		mcp.EntityCreateInput{ContextID: createdContext.ContextID, Kind: "device", Label: "MCP router"})
	if failed {
		t.Fatalf("MCP entity create failed: %s", createdEntityData)
	}
	var createdEntity mcp.EntityItemResult
	if err := json.Unmarshal(createdEntityData, &createdEntity); err != nil ||
		createdEntity.ID == "" || createdEntity.ContextID != createdContext.ContextID {
		t.Fatalf("MCP entity create result: %+v %v", createdEntity, err)
	}
	if _, failed := nativeControlCall(t, mcpServer, operator, "entity_source_assign",
		mcp.EntityAssignInput{AgentID: agentA, SourceKind: "device_target",
			SourceRef: "10.42.0.1", ContextID: ctxB}); !failed {
		t.Fatal("MCP assigned tenant A source into tenant B context")
	}
	t.Run("public-source", func(t *testing.T) {
		for _, fixture := range []struct{ tenant, agent, own, foreign, device string }{
			{a, agentA, ctxA, ctxB, deviceA}, {b, agentB, ctxB, ctxA, deviceB},
		} {
			input := map[string]string{"agent_id": fixture.agent, "source_kind": "public_bgp", "source_ref": "ris/mrt_table_dump_v2/rrc00", "context_id": fixture.own, "anchor_entity_id": fixture.device}
			if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", fixture.tenant, input); rec.Code != http.StatusBadRequest {
				t.Fatal("public source acquired an invented router anchor", rec.Code, rec.Body.String())
			}
			delete(input, "anchor_entity_id")
			input["context_id"] = fixture.foreign
			if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", fixture.tenant, input); rec.Code != http.StatusNotFound {
				t.Fatal("public source assignment accepted a foreign routing context", rec.Code, rec.Body.String())
			}
			principal := *operator
			principal.TenantID = fixture.tenant
			if _, failed := nativeControlCall(t, mcpServer, &principal, "entity_source_assign", input); !failed {
				t.Fatal("native public source assignment accepted a foreign routing context")
			}
			input["context_id"] = fixture.own
			if rec := apiReq(t, h, http.MethodPut, "/v1/entity-source-contexts", fixture.tenant, input); rec.Code != http.StatusOK {
				t.Fatal("REST public source assignment was refused", rec.Code, rec.Body.String())
			}
			if data, failed := nativeControlCall(t, mcpServer, &principal, "entity_source_assign", input); failed {
				t.Fatal("native public source assignment was refused", string(data))
			}
			if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(fixture.tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				var count, anchors int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(anchor_entity_id) FROM entity_source_contexts WHERE source_kind='public_bgp'`).Scan(&count, &anchors); err != nil {
					return err
				}
				if count != 1 || anchors != 0 {
					t.Fatal("served public assignment escaped tenant storage or acquired an anchor", count, anchors)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
	// Legacy registry deletion is still a supported API. Its transaction must
	// close the entity bindings even though an issued SVID may outlive the row.
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Agents{}).Delete(ctx, sc, agentA)
		})
	if err != nil {
		t.Fatalf("delete registered agent: %v", err)
	}
	_, err = store.NewEntityRegistry(db.Pool()).ResolveSourceContext(
		tenancy.WithTenant(context.Background(), tenancy.ID(a)), a,
		entity.SourceKey{AgentID: agentA, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted agent retained live entity source: %v", err)
	}
	got, err := store.NewEntityRegistry(db.Pool()).ResolveSourceContext(
		tenancy.WithTenant(context.Background(), tenancy.ID(b)), b,
		entity.SourceKey{AgentID: agentB, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"})
	if err != nil || got.ContextID != ctxB {
		t.Fatalf("deleting tenant A agent changed tenant B source: %+v %v", got, err)
	}
	_, err = store.NewEntityRegistry(db.Pool()).ResolveSourceContext(tenancy.WithTenant(t.Context(), tenancy.ID(a)), a,
		entity.SourceKey{AgentID: agentA, Kind: entity.PublicBGP, SourceRef: "ris/mrt_table_dump_v2/rrc00"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("deleted collector retained public source authority", err)
	}
	got, err = store.NewEntityRegistry(db.Pool()).ResolveSourceContext(tenancy.WithTenant(t.Context(), tenancy.ID(b)), b,
		entity.SourceKey{AgentID: agentB, Kind: entity.PublicBGP, SourceRef: "ris/mrt_table_dump_v2/rrc00"})
	if err != nil || got.ContextID != ctxB {
		t.Fatal("collector deletion changed sibling public source", got, err)
	}
}
