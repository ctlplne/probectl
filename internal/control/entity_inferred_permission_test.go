// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
)

func TestInferredEntityResolutionNeedsSourceAndSNMPReadPermissions(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	const routingContext = "00000000-0000-4000-8000-000000000201"
	const support = "00000000-0000-4000-8000-000000000301"
	for _, source := range []entity.SourceKind{entity.FlowExporter, entity.BMPPeer} {
		t.Run(string(source), func(t *testing.T) {
			result := entity.Resolution{Scope: entity.Scope{TenantID: tenant, ContextID: routingContext}, Candidates: []entity.Claim{{
				SourceKey:         entity.SourceKey{Kind: source},
				SupportEvidenceID: support,
			}}}
			base := &auth.Principal{TenantID: tenant, UserID: "reader",
				Permissions: map[string]bool{"entities.read": true, entitySourcePermission(source): true}}
			server := &Server{}
			resource := entityScopeResource(result.Scope)
			if err := server.authorizeEntityResolution(context.Background(), base, result, resource); err == nil {
				t.Fatal("REST resolution exposed an SNMP-backed identity to a source-only reader")
			}
			if entityMCPResolutionAllowed(base, nil, result, resource) {
				t.Fatal("MCP resolution exposed an SNMP-backed identity to a source-only reader")
			}
			base.Permissions[entitySourcePermission(entity.DeviceTarget)] = true
			if err := server.authorizeEntityResolution(context.Background(), base, result, resource); err != nil {
				t.Fatalf("REST refused both authorized source planes: %v", err)
			}
			if !entityMCPResolutionAllowed(base, nil, result, resource) {
				t.Fatal("MCP refused both authorized source planes")
			}
		})
	}
}

func TestEntityContextPolicyDeniesUnresolvedAndSourceBackedMCPResolution(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	const deniedContext = "00000000-0000-4000-8000-000000000201"
	const allowedContext = "00000000-0000-4000-8000-000000000202"
	principal := &auth.Principal{TenantID: tenant, UserID: "reader", Permissions: map[string]bool{
		"entities.read": true, entitySourcePermission(entity.FlowExporter): true,
	}}
	policies := []auth.Policy{{Name: "blocked routing context", Enabled: true, Effect: auth.PolicyDeny,
		Permission: "*", Resource: map[string]string{"context_id": deniedContext}}}
	for _, sourceBacked := range []bool{false, true} {
		result := entity.Resolution{Scope: entity.Scope{TenantID: tenant, ContextID: deniedContext}}
		if sourceBacked {
			result.Candidates = []entity.Claim{{SourceKey: entity.SourceKey{Kind: entity.FlowExporter}}}
		}
		if entityMCPResolutionAllowed(principal, policies, result, entityScopeResource(result.Scope)) {
			t.Fatal("denied context reached MCP entity resolution")
		}
		result.Scope.ContextID = allowedContext
		if !entityMCPResolutionAllowed(principal, policies, result, entityScopeResource(result.Scope)) {
			t.Fatal("allowed context was rejected")
		}
	}
}

func TestEntityContextPolicyDeniesRESTResolution(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	const deniedContext = "00000000-0000-4000-8000-000000000201"
	const allowedContext = "00000000-0000-4000-8000-000000000202"
	principal := &auth.Principal{TenantID: tenant, UserID: "reader", Permissions: map[string]bool{
		"entities.read": true, entitySourcePermission(entity.FlowExporter): true,
	}}
	policies := []auth.Policy{{Name: "blocked routing context", Enabled: true, Effect: auth.PolicyDeny,
		Permission: "*", Resource: map[string]string{"context_id": deniedContext}}}
	server := &Server{abac: &abacCache{load: func(context.Context, string) ([]auth.Policy, error) {
		return policies, nil
	}}}
	for _, sourceBacked := range []bool{false, true} {
		result := entity.Resolution{Scope: entity.Scope{TenantID: tenant, ContextID: deniedContext}}
		if sourceBacked {
			result.Candidates = []entity.Claim{{SourceKey: entity.SourceKey{Kind: entity.FlowExporter}}}
		}
		if err := server.authorizeEntityResolution(context.Background(), principal, result, entityScopeResource(result.Scope)); err == nil {
			t.Fatal("denied context reached REST entity resolution")
		}
		result.Scope.ContextID = allowedContext
		if err := server.authorizeEntityResolution(context.Background(), principal, result, entityScopeResource(result.Scope)); err != nil {
			t.Fatalf("allowed context was rejected: %v", err)
		}
	}
}

func TestStoredSitePolicyAttributesDenyRESTAndMCPResolution(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	const routingContext = "00000000-0000-4000-8000-000000000201"
	principal := &auth.Principal{TenantID: tenant, UserID: "reader", Permissions: map[string]bool{
		"entities.read": true,
	}}
	policies := []auth.Policy{{Name: "blocked site", Enabled: true, Effect: auth.PolicyDeny,
		Permission: "entities.read", Resource: map[string]string{"site_label": "West DC"}}}
	resource := entityContextResource(entity.ContextRecord{TenantID: tenant, ContextID: routingContext,
		SiteLabel: "West DC", VRFLabel: "Private VRF"})
	result := entity.Resolution{Scope: entity.Scope{TenantID: tenant, ContextID: routingContext}}
	if entityMCPResolutionAllowed(principal, policies, result, resource) {
		t.Fatal("site deny did not apply to unresolved MCP resolution")
	}
	server := &Server{abac: &abacCache{load: func(context.Context, string) ([]auth.Policy, error) {
		return policies, nil
	}}}
	if err := server.authorizeEntityResolution(context.Background(), principal, result, resource); err == nil {
		t.Fatal("site deny did not apply to unresolved REST resolution")
	}
}
