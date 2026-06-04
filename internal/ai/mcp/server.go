package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

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
}

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

// New builds a Server over the backend with the S25 tool catalog.
func New(backend Backend, opts ...Option) *Server {
	s := &Server{
		tools:   map[string]Tool{},
		limiter: newRateLimiter(120),
		info:    ServerInfo{Name: "probectl", Version: version.Get().Version},
		log:     slog.Default(),
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
	// RBAC: the caller must hold the tool's permission (tenant already checked) —
	// the out-of-scope caller gets nothing.
	if !p.Has(t.Permission) {
		return errorResponse(req.ID, codeForbidden, "missing permission: "+t.Permission)
	}
	if !s.limiter.allow(p.TenantID) {
		return errorResponse(req.ID, codeRateLimited, "rate limit exceeded for tenant")
	}
	out, err := t.Invoke(ctx, p, params.Arguments)
	if err != nil {
		// A tool error is returned as an isError tool result (MCP idiom) so the
		// model can read the message, not as a transport error.
		return resultResponse(req.ID, toolResult(err.Error(), nil, true))
	}
	return resultResponse(req.ID, toolResult("", out, false))
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
