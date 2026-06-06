package mcp

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// Backend is the data seam the MCP tools call. Each method is given the
// authenticated principal and MUST scope its work to that principal's tenant
// (the control-plane implementation goes through the tenant-scoped stores + the
// S23 query layer, so it cannot return another tenant's data). Methods return an
// already-shaped result object (serialized into the tool result) or an error
// (surfaced to the model as an isError tool result). The mcp package keeps this
// interface so it stays free of store/DB dependencies and is unit-testable with a
// fake backend.
type Backend interface {
	ListTests(ctx context.Context, p *auth.Principal) (any, error)
	GetPath(ctx context.Context, p *auth.Principal, target string) (any, error)
	GetBGPEvents(ctx context.Context, p *auth.Principal, prefix, asn string, limit int) (any, error)
	QueryFlows(ctx context.Context, p *auth.Principal, service, src, dst string, limit int) (any, error)
	GetIncident(ctx context.Context, p *auth.Principal, id string) (any, error)
	CorrelateIncident(ctx context.Context, p *auth.Principal, id string) (any, error)
	ExplainDegradation(ctx context.Context, p *auth.Principal, question string, subject map[string]string) (any, error)
	// ProposeRemediation files a guarded-remediation PROPOSAL (S-EE5). It is
	// PROPOSAL-ONLY: it can only ever create a state=proposed suggestion a
	// human must approve via the authenticated UI — ingested data (a
	// prompt-injection) can at most file a proposal, never approve or execute.
	ProposeRemediation(ctx context.Context, p *auth.Principal, kind, title, rationale, target, incidentID string) (any, error)
}
