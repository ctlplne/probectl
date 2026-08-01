// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mcp

import (
	"context"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
)

// Backend is the data seam the MCP tools call. Each method is given the
// authenticated principal and MUST scope its work to that principal's tenant
// (the control-plane implementation goes through the tenant-scoped stores + the
// S23 query layer, so it cannot return another tenant's data).
//
// Every method returns a DECLARED result type (results.go), never `any`
// (S-063994f7). That is the field discipline, expressed where it cannot be
// skipped: an implementation must project its store objects into these structs,
// so a column added to a table is dropped at this boundary by default instead of
// being published to an external AI client by accident. The mcp package keeps
// this interface so it stays free of store/DB dependencies and is unit-testable
// with a fake backend.
type Backend interface {
	ListTests(ctx context.Context, p *auth.Principal) (TestsResult, error)
	GetPath(ctx context.Context, p *auth.Principal, target string) (PathResult, error)
	GetBGPEvents(ctx context.Context, p *auth.Principal, prefix, asn string, limit int) (EventsResult, error)
	QueryFlows(ctx context.Context, p *auth.Principal, service, src, dst string, limit int) (EventsResult, error)
	GetIncident(ctx context.Context, p *auth.Principal, id string) (IncidentResult, error)
	CorrelateIncident(ctx context.Context, p *auth.Principal, id string) (CorrelationResult, error)
	ExplainDegradation(ctx context.Context, p *auth.Principal, question string, subject map[string]string) (ai.Answer, error)
	// ProposeRemediation files a guarded-remediation PROPOSAL (S-EE5). It is
	// PROPOSAL-ONLY: it can only ever create a state=proposed suggestion a
	// human must approve via the authenticated UI — ingested data (a
	// prompt-injection) can at most file a proposal, never approve or execute.
	ProposeRemediation(ctx context.Context, p *auth.Principal, kind, title, rationale, target, incidentID string) (ProposalResult, error)
}
