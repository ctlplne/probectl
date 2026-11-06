// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/entity"
)

func TestInterfaceRoleMCPMetadataKeepsExactGeneratedIDsAndFullTextRedaction(t *testing.T) {
	const id = "40000000-0000-4004-8000-abcdefabcdef"
	const revision = "4111111111111111"
	const card = "4111-1111-1111-1111"
	secret := "fixture-private-" + strings.Repeat("x", 20)
	input := entity.InterfaceRolePolicyRecord{Scope: entity.Scope{TenantID: id, ContextID: id}, ID: id, Revision: revision,
		Definition: entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{4294967295}, CustomerASNs: []uint32{}, DescriptionRules: []entity.InterfaceRoleDescriptionRule{{ID: id, Role: entity.InterfaceRoleBackbone, Pattern: "password=" + secret + " card=" + card + " password=" + id}}}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalRoleMCPPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, id)
	var result entity.InterfaceRolePolicyRecord
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Fatal(err)
	}
	if result.TenantID != id || result.ContextID != id || result.ID != id || result.Revision != revision || len(result.Definition.DescriptionRules) != 1 || result.Definition.DescriptionRules[0].ID != id {
		t.Fatal("native role redaction altered generated structural identity", result.ID, result.Revision)
	}
	pattern := result.Definition.DescriptionRules[0].Pattern
	if strings.Contains(pattern, secret) || strings.Contains(pattern, card) || strings.Contains(pattern, id) || !strings.Contains(pattern, "[secret:") || !strings.Contains(pattern, "[pan:") {
		t.Fatal("native role metadata encoding weakened text redaction", pattern)
	}
	source := roleMCPSource("policy/" + id + "/" + revision + "/rule/" + id)
	encoded, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var ref string
	if json.Unmarshal([]byte(ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, id)), &ref) != nil || ref != string(source) {
		t.Fatal("native role configuration reference lost exact generated identity", ref)
	}
	// Untrusted evidence/sender identifiers never receive the configuration
	// metadata encoding, even if a sender picks a canonical UUID-shaped value.
	encoded, err = json.Marshal(roleMCPSource("evidence/" + id))
	if err != nil {
		t.Fatal(err)
	}
	if red := ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, id); strings.Contains(red, id) || !strings.Contains(red, "[pan:") {
		t.Fatal("untrusted evidence identity bypassed the redaction floor", red)
	}
	// A valid server hash can also contain a checksum-shaped numeric run.
	// Preserve only that typed digest; addresses and arbitrary reasons still mask.
	digest := revision + strings.Repeat("a", 48)
	encoded, err = json.Marshal(mcp.NativeFlowResult{RoleTenantID: mcp.NativeRoleUUID(id), RoleDigest: mcp.NativeRoleDigest(digest), RoleSources: []mcp.NativeFlowRoleSource{{TenantID: mcp.NativeRoleUUID(id), Exporter: "192.0.2.1", Reason: "password=" + secret}}})
	if err != nil {
		t.Fatal(err)
	}
	var projected mcp.NativeFlowResult
	redacted = ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, id)
	if json.Unmarshal([]byte(redacted), &projected) != nil || string(projected.RoleDigest) != digest || string(projected.RoleTenantID) != id || strings.Contains(redacted, "192.0.2.1") || strings.Contains(redacted, secret) {
		t.Fatal("native role flow metadata changed identity or weakened value redaction")
	}
}

func TestInterfaceRoleMCPMetadataRefusesMalformedIdentifiersAndRevisions(t *testing.T) {
	for _, value := range []string{"4111111111111111", "not-an-id", "40000000-0000-4004-8000-ABCDEFABCDEF"} {
		if _, err := json.Marshal(roleMCPUUID(value)); err == nil {
			t.Fatal("untyped data acquired role metadata encoding", value)
		}
	}
	for _, value := range []string{"", "-1", "01", "9223372036854775808", "password=private"} {
		if _, err := json.Marshal(roleMCPRevision(value)); err == nil {
			t.Fatal("invalid revision acquired role metadata encoding", value)
		}
	}
	for _, value := range []string{"", "4111111111111111", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := json.Marshal(mcp.NativeRoleDigest(value)); err == nil {
			t.Fatal("invalid digest acquired role metadata encoding", value)
		}
	}
}
