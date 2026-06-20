// SPDX-License-Identifier: LicenseRef-probectl-TBD

package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// ServerInfo identifies the server in the initialize handshake.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server is probectl's MCP server: a transport-agnostic JSON-RPC handler over the
// read-only tool catalog. Handle is the single entry point both transports use.
type Server struct {
	tools   map[string]Tool
	order   []string
	limiter *rateLimiter
	info    ServerInfo
	log     *slog.Logger
	gate    *ai.EgressGate
	audit   CallAudit
}

// CallEvent records one MCP tool call for the audit trail (AIRCA-003): WHO
// (tenant + user), WHAT (tool), and the OUTCOME — including consent denials.
type CallEvent struct {
	TenantID string
	UserID   string
	Tool     string
	Allowed  bool
	Denial   string // "" when allowed; "consent"|"permission"|"rate" otherwise
}

// CallAudit observes every MCP tool call (the control plane appends it to
// the tenant's tamper-evident audit stream as "mcp.tool_call").
type CallAudit func(ctx context.Context, ev CallEvent)

// Option configures a Server.
type Option func(*Server)

// WithRateLimit sets the per-tenant tool-call rate (calls/minute; <=0 disables).
func WithRateLimit(perMinute int) Option {
	return func(s *Server) { s.limiter = newRateLimiter(perMinute) }
}

// WithLogger sets the server logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.log = l
		}
	}
}

// WithCallAudit sets the per-call audit hook (AIRCA-003).
func WithCallAudit(h CallAudit) Option {
	return func(s *Server) { s.audit = h }
}

// New builds a Server over the backend with the S25 tool catalog.
//
// The egress gate is a REQUIRED constructor argument (AIRCA-001): MCP tool
// results are tenant telemetry leaving to an external AI client, so every
// call is consent-gated and redacted by the same gate as the RCA and
// authoring paths. There is deliberately no gate-less constructor — a nil
// gate denies every tool call (fail closed).
func New(backend Backend, gate *ai.EgressGate, opts ...Option) *Server {
	s := &Server{
		tools:   map[string]Tool{},
		limiter: newRateLimiter(120),
		info:    ServerInfo{Name: "probectl", Version: version.Get().Version},
		log:     slog.Default(),
		gate:    gate,
	}
	for _, t := range buildTools(backend) {
		s.tools[t.Name] = t
		s.order = append(s.order, t.Name)
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handle processes one JSON-RPC message under the principal's tenant + RBAC and
// returns the response bytes — or nil for a notification (which gets no reply).
func (s *Server) Handle(ctx context.Context, p *auth.Principal, raw []byte) []byte {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return marshal(errorResponse(nil, codeParse, "parse error"))
	}
	notification := len(req.ID) == 0
	resp := s.dispatch(ctx, p, req)
	if notification || resp == nil {
		return nil
	}
	return marshal(resp)
}

func (s *Server) dispatch(ctx context.Context, p *auth.Principal, req rpcRequest) *rpcResponse {
	// Tenant boundary FIRST (fail closed). An MCP caller is bound to one tenant.
	if p == nil || p.TenantID == "" {
		if len(req.ID) == 0 {
			return nil
		}
		return errorResponse(req.ID, codeUnauthorized, "no tenant on principal")
	}
	switch req.Method {
	case "initialize":
		return resultResponse(req.ID, s.initializeResult())
	case "notifications/initialized":
		return nil // a notification — no response
	case "ping":
		return resultResponse(req.ID, struct{}{})
	case "tools/list":
		return resultResponse(req.ID, s.listTools(p))
	case "tools/call":
		return s.callTool(ctx, p, req)
	default:
		if len(req.ID) == 0 {
			return nil // unknown notification — ignore
		}
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) initializeResult() map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      s.info,
	}
}

type toolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// listTools returns only the tools the caller is permitted to use — an
// out-of-scope caller does not even see a tool it cannot call.
func (s *Server) listTools(p *auth.Principal) map[string]any {
	tools := make([]toolDescriptor, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		if !p.Has(t.Permission) {
			continue
		}
		tools = append(tools, toolDescriptor{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return map[string]any{"tools": tools}
}

func (s *Server) callTool(ctx context.Context, p *auth.Principal, req rpcRequest) *rpcResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, codeInvalidParams, "invalid params")
	}
	t, ok := s.tools[params.Name]
	if !ok {
		return errorResponse(req.ID, codeMethodNotFound, "unknown tool: "+params.Name)
	}
	// Every outcome below is audited (AIRCA-003): who, tenant, tool, result.
	emit := func(allowed bool, denial string) {
		if s.audit != nil {
			s.audit(ctx, CallEvent{TenantID: p.TenantID, UserID: p.UserID, Tool: params.Name, Allowed: allowed, Denial: denial})
		}
	}
	// Tenant boundary FIRST, then RBAC (the documented MCP order) — routed through
	// the single auth.Authorize decision. The tool acts within the caller's own
	// tenant, so the resource is tagged with it; a future cross-tenant resource
	// would fail closed at the boundary before RBAC is even consulted. An
	// out-of-scope caller gets nothing.
	if !auth.Authorize(p, t.Permission, nil, map[string]string{auth.ResourceTenantKey: p.TenantID}) {
		emit(false, "permission")
		return errorResponse(req.ID, codeForbidden, "missing permission: "+t.Permission)
	}
	if !s.limiter.allow(p.TenantID) {
		emit(false, "rate")
		return errorResponse(req.ID, codeRateLimited, "rate limit exceeded for tenant")
	}
	// AIRCA-001: the MCP caller is an EXTERNAL AI CLIENT — returning tool
	// output is tenant telemetry egressing the platform. The same per-tenant
	// consent that gates the remote RCA model gates this (default deny), and
	// the gate's redaction policy is applied to everything returned.
	if err := s.gate.Authorize(ctx, p.TenantID); err != nil {
		emit(false, "consent")
		return resultResponse(req.ID, toolResult(err.Error(), nil, true))
	}
	out, err := t.Invoke(ctx, p, params.Arguments)
	if err != nil {
		emit(true, "")
		// A tool error is returned as an isError tool result (MCP idiom) so the
		// model can read the message, not as a transport error.
		return resultResponse(req.ID, toolResult(s.gate.RedactForTenant(err.Error(), p.TenantID), nil, true))
	}
	emit(true, "")
	s.gate.Emit(ctx, ai.EgressEvent{TenantID: p.TenantID, Endpoint: "mcp-client", Model: "mcp", Surface: "mcp"})
	res, rerr := s.redactedResult(p.TenantID, out)
	if rerr != nil {
		return errorResponse(req.ID, codeInternal, "tool result encoding failed")
	}
	return resultResponse(req.ID, res)
}

// redactedResult renders a tool's output ONCE through the gate's redaction
// (C8/AIRCA-002) and returns the MCP result carrying the redacted text and
// the redacted structured content — the un-redacted object never reaches
// the wire. Masking happens on the JSON encoding; tenant-scoped deterministic
// tokens keep the JSON valid and values correlatable only inside the tenant.
func (s *Server) redactedResult(tenantID string, out any) (map[string]any, error) {
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	red := s.gate.RedactForTenant(string(b), tenantID)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": red}},
		"structuredContent": json.RawMessage(red),
	}, nil
}

// toolResult builds an MCP tool result. On success it carries both a text
// rendering (most clients read this) and structuredContent (the raw object).
func toolResult(text string, structured any, isErr bool) map[string]any {
	if structured != nil && text == "" {
		if b, err := json.MarshalIndent(structured, "", "  "); err == nil {
			text = string(b)
		}
	}
	res := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
	if structured != nil {
		res["structuredContent"] = structured
	}
	if isErr {
		res["isError"] = true
	}
	return res
}
