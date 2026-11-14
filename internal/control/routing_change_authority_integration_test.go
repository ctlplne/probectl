// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestOwnedRoutingTimelineKeepsCurrentTenantSourceAndLatePublicationAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	originals := map[string]change.Event{}
	for lane, tenant := range f.tenants {
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permChangeRead, ai.PermEventsRead, "ai.query"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			events, err := (store.ChangeEvents{}).List(ctx, sc, 200)
			if err != nil {
				return err
			}
			if len(events) != 1 || events[0].Routing == nil {
				t.Fatal("accepted owned router did not append its original timeline reference", len(events))
			}
			originals[tenant] = events[0]
			return nil
		})
	}
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	read := func(tenant string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/changes", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	for _, tenant := range f.tenants {
		code, body := read(tenant)
		var result struct{ Items []change.Event }
		if code != http.StatusOK || json.Unmarshal([]byte(body), &result) != nil || len(result.Items) != 1 || result.Items[0].ID != originals[tenant].ID || result.Items[0].Routing == nil || *result.Items[0].Routing != *originals[tenant].Routing {
			t.Fatal("served owned routing reference changed its original metadata", code, body)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	request := httptest.NewRequest(http.MethodGet, "/v1/changes", nil)
	request.Header.Set("Authorization", "Bearer "+f.tokens[a])
	actor := f.server.resolvePrincipal(request)
	if actor == nil {
		t.Fatal("missing current source actor")
	}
	request = request.WithContext(auth.WithPrincipal(request.Context(), actor))
	scope := f.server.configEvidenceForRequest(request, permChangeRead)
	if err := scope.retain(originals[a]); err != nil {
		t.Fatal(err)
	}
	if err := scope.check(t.Context()); err != nil {
		t.Fatal("unchanged originals refused", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	if err := scope.check(t.Context()); err == nil {
		t.Fatal("late source removal published an owned route")
	}
	if code, body := read(a); code == http.StatusOK || strings.Contains(body, originals[a].ID) {
		t.Fatal("revoked source published routing evidence", code)
	}
	if code, _ := read(b); code != http.StatusOK {
		t.Fatal("source removal damaged sibling tenant", code)
	}
}
