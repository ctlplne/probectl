// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// These named projections keep the MCP field boundary closed when registry
// storage gains columns. No tenant hint enters an input; the principal selects
// the FORCE-RLS transaction before the backend reads or writes anything.
type EntityItemResult struct {
	ID            string    `json:"id"`
	ContextID     string    `json:"context_id"`
	Kind          string    `json:"kind"`
	Label         string    `json:"label"`
	NetworkPrefix string    `json:"network_prefix,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type EntityListResult struct {
	Items      []EntityItemResult `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type EntityEvidenceResult struct {
	ID                   string    `json:"id"`
	ObservationID        string    `json:"observation_id"`
	SupportEvidenceID    string    `json:"support_evidence_id,omitempty"`
	AliasKind            string    `json:"alias_kind"`
	AliasValue           string    `json:"alias_value"`
	Source               string    `json:"source"`
	SourceRef            string    `json:"source_ref"`
	AgentID              string    `json:"agent_id"`
	SourceKind           string    `json:"source_kind"`
	ConfiguredRef        string    `json:"configured_ref"`
	InterfaceName        string    `json:"interface_name,omitempty"`
	InterfaceDescription string    `json:"interface_description,omitempty"`
	NeighborProtocol     string    `json:"neighbor_protocol,omitempty"`
	NeighborLocalIfIndex uint32    `json:"neighbor_local_if_index,omitempty"`
	NeighborLocalPortID  string    `json:"neighbor_local_port_id,omitempty"`
	NeighborRemotePortID string    `json:"neighbor_remote_port_id,omitempty"`
	NeighborChassisID    string    `json:"neighbor_chassis_id,omitempty"`
	NeighborDeviceName   string    `json:"neighbor_device_name,omitempty"`
	NeighborAddress      string    `json:"neighbor_management_address,omitempty"`
	ObservedAt           time.Time `json:"observed_at"`
	Current              bool      `json:"current"`
}

type EntityEvidenceListResult struct {
	EntityID   string                 `json:"entity_id"`
	Items      []EntityEvidenceResult `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type EntityLinkResult struct {
	ID           string    `json:"id"`
	FromEntityID string    `json:"from_entity_id"`
	ToEntityID   string    `json:"to_entity_id"`
	EvidenceID   string    `json:"evidence_id"`
	Kind         string    `json:"kind"`
	SourceKind   string    `json:"source_kind"`
	ObservedAt   time.Time `json:"observed_at"`
}

type EntityLinkListResult struct {
	EntityID   string             `json:"entity_id"`
	Items      []EntityLinkResult `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type EntityContextResult struct {
	ContextID string `json:"context_id"`
	SiteID    string `json:"site_id"`
	VRFID     string `json:"vrf_id"`
	SiteLabel string `json:"site_label"`
	VRFLabel  string `json:"vrf_label"`
}

type EntityContextListResult struct {
	Items      []EntityContextResult `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type EntityCandidateResult struct {
	EntityID          string    `json:"entity_id"`
	EvidenceID        string    `json:"evidence_id"`
	SupportEvidenceID string    `json:"support_evidence_id,omitempty"`
	SourceKind        string    `json:"source_kind"`
	SourceRef         string    `json:"source_ref"`
	AgentID           string    `json:"agent_id"`
	ObservedAt        time.Time `json:"observed_at"`
}

type EntityResolutionResult struct {
	ContextID      string                  `json:"context_id"`
	Status         string                  `json:"status"`
	EntityID       string                  `json:"entity_id,omitempty"`
	Candidates     []EntityCandidateResult `json:"candidates,omitempty"`
	MoreCandidates bool                    `json:"more_candidates"`
}

type EntityAssignmentResult struct {
	AgentID        string `json:"agent_id"`
	SourceKind     string `json:"source_kind"`
	SourceRef      string `json:"source_ref"`
	ContextID      string `json:"context_id"`
	AnchorEntityID string `json:"anchor_entity_id,omitempty"`
}

type EntityPathContextInput struct {
	TestID    string `json:"test_id"`
	ContextID string `json:"context_id"`
}

type EntityPathContextResult struct {
	TestID    string `json:"test_id"`
	ContextID string `json:"context_id"`
}

type EntityPathResolveInput struct {
	TestID string `json:"test_id"`
}

type EntityPathHopResult struct {
	TTL        int                    `json:"ttl"`
	IP         string                 `json:"ip"`
	Resolution EntityResolutionResult `json:"resolution"`
}

type EntityPathResult struct {
	TestID    string                `json:"test_id"`
	ContextID string                `json:"context_id,omitempty"`
	Status    string                `json:"status"`
	Items     []EntityPathHopResult `json:"items"`
	Truncated bool                  `json:"truncated"`
}

type EntityListInput struct {
	ContextID string `json:"context_id"`
	Cursor    string `json:"cursor"`
	Limit     int    `json:"limit"`
}
type EntityContextListInput struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}
type EntityContextCreateInput struct {
	SiteLabel string `json:"site_label"`
	VRFLabel  string `json:"vrf_label"`
}
type EntityCreateInput struct {
	ContextID     string `json:"context_id"`
	Kind          string `json:"kind"`
	Label         string `json:"label"`
	NetworkPrefix string `json:"network_prefix,omitempty"`
}

type EntityNetworkPrefixInput struct {
	ContextID     string  `json:"context_id"`
	ID            string  `json:"id"`
	NetworkPrefix *string `json:"network_prefix"`
}

// This optional write extension keeps older read/configuration backends from
// advertising a mutation they cannot implement.
type EntityNetworkPrefixBackend interface {
	EntityNetworkPrefixSet(context.Context, *auth.Principal, EntityNetworkPrefixInput) (EntityItemResult, error)
}
type EntityGetInput struct {
	ContextID string `json:"context_id"`
	ID        string `json:"id"`
}
type EntityDetailListInput struct {
	ContextID string `json:"context_id"`
	ID        string `json:"id"`
	Cursor    string `json:"cursor"`
	Limit     int    `json:"limit"`
}
type EntityResolveInput struct {
	ContextID string `json:"context_id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
}
type EntityAssignInput struct {
	AgentID        string `json:"agent_id"`
	SourceKind     string `json:"source_kind"`
	SourceRef      string `json:"source_ref"`
	ContextID      string `json:"context_id"`
	AnchorEntityID string `json:"anchor_entity_id"`
}

type EntityBackend interface {
	EntityContextList(context.Context, *auth.Principal, EntityContextListInput) (EntityContextListResult, error)
	EntityContextCreate(context.Context, *auth.Principal, EntityContextCreateInput) (EntityContextResult, error)
	EntityCreate(context.Context, *auth.Principal, EntityCreateInput) (EntityItemResult, error)
	EntityList(context.Context, *auth.Principal, EntityListInput) (EntityListResult, error)
	EntityGet(context.Context, *auth.Principal, EntityGetInput) (EntityItemResult, error)
	EntityEvidenceList(context.Context, *auth.Principal, EntityDetailListInput) (EntityEvidenceListResult, error)
	EntityLinkList(context.Context, *auth.Principal, EntityDetailListInput) (EntityLinkListResult, error)
	EntityResolve(context.Context, *auth.Principal, EntityResolveInput) (EntityResolutionResult, error)
	EntityAssign(context.Context, *auth.Principal, EntityAssignInput) (EntityAssignmentResult, error)
	EntityPathContextAssign(context.Context, *auth.Principal, EntityPathContextInput) (EntityPathContextResult, error)
	EntityPathResolve(context.Context, *auth.Principal, EntityPathResolveInput) (EntityPathResult, error)
}

func WithEntityBackend(backend EntityBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, tool := range buildEntityTools(backend) {
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
		if writer, ok := backend.(EntityNetworkPrefixBackend); ok {
			tool := entityTool("entity_network_prefix_set", "Set or clear explicit operator network metadata on an owned prefix without changing its ID; audited.", "agent.write",
				json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"id":{"type":"string"},"network_prefix":{"type":"string","maxLength":128}},"required":["context_id","id","network_prefix"],"additionalProperties":false}`), writer.EntityNetworkPrefixSet)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}

func entityTool[A, R any](name, description, permission string, schema json.RawMessage,
	invoke func(context.Context, *auth.Principal, A) (R, error)) Tool {
	return Tool{
		Name: name, Description: description, Permission: permission,
		InputSchema: schema, RequiresUser: true,
		Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
			var args A
			if err := decodeNativeArgs(raw, &args); err != nil {
				return nil, argErr("invalid entity arguments")
			}
			return invoke(ctx, p, args)
		},
	}
}

func buildEntityTools(b EntityBackend) []Tool {
	return []Tool{
		entityTool("entity_context_list", "Page the caller tenant's operator-configured site and VRF contexts.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"additionalProperties":false}`), b.EntityContextList),
		entityTool("entity_context_create", "Create a tenant-owned named site/VRF routing context; the server mints its UUIDs and audits the write.",
			"agent.write", json.RawMessage(`{"type":"object","properties":{"site_label":{"type":"string"},"vrf_label":{"type":"string"}},"required":["site_label","vrf_label"],"additionalProperties":false}`), b.EntityContextCreate),
		entityTool("entity_create", "Create an operator-managed canonical entity in one routing context; audited in the tenant transaction.",
			"agent.write", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"kind":{"type":"string","enum":["device","interface","address","prefix","service","site","customer"]},"label":{"type":"string"},"network_prefix":{"type":"string","maxLength":128}},"required":["context_id","kind","label"],"additionalProperties":false}`), b.EntityCreate),
		entityTool("entity_list", "Page canonical entities in one explicit routing context.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id"],"additionalProperties":false}`), b.EntityList),
		entityTool("entity_get", "Read one tenant-owned canonical entity in one explicit routing context.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"id":{"type":"string"}},"required":["context_id","id"],"additionalProperties":false}`), b.EntityGet),
		entityTool("entity_evidence_list", "Page one canonical entity's original evidence; each source requires its plane read permission.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"id":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id","id"],"additionalProperties":false}`), b.EntityEvidenceList),
		entityTool("entity_link_list", "Page one canonical entity's typed evidence-backed links; each source requires its plane read permission.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"id":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id","id"],"additionalProperties":false}`), b.EntityLinkList),
		entityTool("entity_resolve", "Resolve one typed alias with bounded provenance; conflicts stay explicit and require each source's read permission.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"kind":{"type":"string"},"value":{"type":"string"}},"required":["context_id","kind","value"],"additionalProperties":false}`), b.EntityResolve),
		entityTool("entity_source_assign", "Explicitly assign one registered evidence source to one operator-owned context and optional canonical anchor; audited in the tenant transaction.",
			"agent.write", json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"source_kind":{"type":"string","enum":["device_target","flow_exporter","path_agent","bmp_peer","agent_site"]},"source_ref":{"type":"string"},"context_id":{"type":"string"},"anchor_entity_id":{"type":"string"}},"required":["agent_id","source_kind","source_ref","context_id"],"additionalProperties":false}`), b.EntityAssign),
		entityTool("entity_path_context_assign", "Audit an owned test context binding; a targetless noop receives metadata context only and no path authority.",
			"agent.write", json.RawMessage(`{"type":"object","properties":{"test_id":{"type":"string"},"context_id":{"type":"string"}},"required":["test_id","context_id"],"additionalProperties":false}`), b.EntityPathContextAssign),
		entityTool("entity_path_resolve", "Read current canonical evidence for responders of a path discovered after its assigned context; returns awaiting_trace until a fresh path exists. Requires test and entity reads plus source reads.",
			"entities.read", json.RawMessage(`{"type":"object","properties":{"test_id":{"type":"string"}},"required":["test_id"],"additionalProperties":false}`), b.EntityPathResolve),
	}
}
