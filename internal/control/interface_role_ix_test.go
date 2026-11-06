// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func roleIXEnricher(t *testing.T, observed time.Time, prefix string) *opendata.Enricher {
	t.Helper()
	body, err := json.Marshal(map[string]any{"version": 1, "object": "ixpfx", "observed_at": observed, "complete": true, "record_count": 1, "data": []map[string]any{{"id": 7, "ixlan_id": 11, "protocol": "IPv4", "prefix": prefix, "status": "ok"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ixpfx.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	en, ok := BuildEnrichment(&config.Config{FlowEnrichIXPrefixFile: path, FlowEnrichIXPrefixMaxAge: time.Hour, FlowQueryMemoryBytes: 2 << 30, FlowEnrichCacheMax: 16}, statusQuietLog())
	if !ok || len(en.Status()) != 1 || en.Status()[0].Health.Status != "ok" {
		t.Fatal("local IX source was not registered independently", ok, en.Status())
	}
	return en
}

func TestInterfaceRoleIXSourceMatchesOnlyOwnedCurrentInputsAndPreservesOverrides(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(tenant, func(t *testing.T) {
			in := roleExplanationFixture(tenant)
			in.AsOf = time.Now().UTC()
			in.SNMP.ObservedAt = in.AsOf.Add(-time.Minute)
			in.SNMP.ValidUntil = in.AsOf.Add(time.Hour)
			in.Policy.Definition = entity.InterfaceRolePolicyDefinition{}
			in.Peers = nil
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			server := &Server{openDataEnricher: roleIXEnricher(t, in.AsOf.Add(-time.Minute), "198.51.100.0/24")}
			snapshot := server.interfaceRoleIXSnapshot(in.AsOf)
			matches, err := matchInterfaceRoleIXInputs(ctx, in, snapshot, interfaceRoleEvaluationBudget())
			if err != nil || len(matches) != 1 {
				t.Fatal("owned IX source addresses did not match", matches, err)
			}
			result, err := explainInterfaceRoleInputs(ctx, in, matches, interfaceRoleEvaluationBudget())
			if err != nil || result.Role != interfaceRoleIX || !strings.Contains(strings.Join(result.Sources, ","), "/ixlan/11/snapshot/"+snapshot.Version) {
				t.Fatal("owned IX explanation lost versioned LAN source", result, err)
			}
			foreign := in
			foreign.Scope.TenantID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			if _, err := matchInterfaceRoleIXInputs(ctx, foreign, snapshot, interfaceRoleEvaluationBudget()); err == nil {
				t.Fatal("foreign tenant facts reached the shared IX cache")
			}
			// Same shared dataset cannot supply a different tenant's interface address.
			in.SNMP.Addresses = []netip.Addr{netip.MustParseAddr("203.0.113.5")}
			absent, err := matchInterfaceRoleIXInputs(ctx, in, snapshot, interfaceRoleEvaluationBudget())
			if err != nil || len(absent) != 0 {
				t.Fatal("IX matcher reused another interface's addresses", absent, err)
			}
			stale := server.interfaceRoleIXSnapshot(in.AsOf.Add(2 * time.Hour))
			absent, err = matchInterfaceRoleIXInputs(ctx, in, stale, interfaceRoleEvaluationBudget())
			if err != nil || len(absent) != 0 || snapshot.SameGeneration(stale) {
				t.Fatal("stale IX source survived publication identity", absent, err)
			}
			in.Override = &entity.InterfaceRoleOverrideRecord{Scope: in.Scope, InterfaceID: in.InterfaceID, ID: "66666666-6666-4666-8666-666666666666", Revision: "1", Role: interfaceRolePrivate}
			result, err = explainInterfaceRoleInputs(ctx, in, absent, interfaceRoleEvaluationBudget())
			if err != nil || result.Role != interfaceRolePrivate || result.Reason != "operator_override" {
				t.Fatal("IX withdrawal lost owned override", result, err)
			}
		})
	}
}

func TestBuildEnrichmentIXPrefixFailureRemainsVisibleAndMakesNoOutboundSource(t *testing.T) {
	en, ok := BuildEnrichment(&config.Config{FlowEnrichIXPrefixFile: filepath.Join(t.TempDir(), "missing"), FlowEnrichIXPrefixMaxAge: time.Hour, FlowQueryMemoryBytes: 2 << 30}, statusQuietLog())
	if !ok || len(en.Status()) != 1 || en.Status()[0].Health.Status != "unavailable" || en.IXPrefixes(time.Now()).Current {
		t.Fatal("broken local IX input was hidden or supplied evidence", ok, en.Status())
	}
}
