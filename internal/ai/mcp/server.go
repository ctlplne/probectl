// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// maxMCPToolResultBytes bounds the complete JSON-RPC response after redaction.
// The same ceiling is applied while constructing a tool result so the text and
// structuredContent copies required by MCP clients cannot amplify without a
// fixed limit.
const (
	maxMCPToolResultBytes = 1 << 20
	// maxMCPRequestIDBytes prevents a caller-controlled JSON-RPC ID from being
	// amplified into every response. The limit includes JSON quotes/escaping.
	maxMCPRequestIDBytes = 4 << 10
	// maxMCPToolResultNodes bounds structural amplification before encoding.
	// Source strings/bytes are separately capped at the wire-byte ceiling.
	maxMCPToolResultNodes = 64 << 10
)

var (
	errToolResultTooLarge   = errors.New("mcp: tool result exceeds byte limit")
	errCallAuditUnavailable = errors.New("mcp: durable call audit is unavailable")
)

// ServerInfo identifies the server in the initialize handshake.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server is probectl's MCP server: a transport-agnostic JSON-RPC handler over the
// read-only tool catalog. Handle is the single entry point both transports use.
type Server struct {
	tools        map[string]Tool
	order        []string
	limiter      *rateLimiter
	info         ServerInfo
	log          *slog.Logger
	gate         *ai.EgressGate
	audit        CallAudit
	policyLoader PolicyLoader
}

const (
	// CallPhaseAdmission is the mandatory pre-read authorization receipt.
	CallPhaseAdmission = "admission"
	// CallPhaseTerminal is the final outcome receipt written before any result
	// leaves the process.
	CallPhaseTerminal = "terminal"
)

// CallEvent records one MCP tool-call transition for the audit trail
// (AIRCA-003): WHO (tenant + user), WHAT (tool), and whether this is the
// pre-read admission or terminal outcome.
type CallEvent struct {
	TenantID string
	UserID   string
	Tool     string
	Phase    string
	Allowed  bool
	Denial   string // bounded reason; empty for an admitted/successful transition
}

// CallAudit durably records every MCP tool call in the tenant's tamper-evident
// audit stream. Returning an error blocks tool invocation/output.
type CallAudit func(ctx context.Context, ev CallEvent) error

// PolicyLoader returns the caller tenant's ABAC policy set. Implementations
// must use tenantID as the storage/query scope and return load failures
// separately from an empty, successfully loaded policy set.
type PolicyLoader func(ctx context.Context, tenantID string) ([]auth.Policy, error)

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

// WithPolicyLoader adds tenant-scoped ABAC deny-override enforcement to MCP
// tool discovery and invocation. A loader error refuses the request.
func WithPolicyLoader(load PolicyLoader) Option {
	return func(s *Server) { s.policyLoader = load }
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
	if len(req.ID) > maxMCPRequestIDBytes {
		// The ID is caller-controlled and is echoed by JSON-RPC. Refuse it
		// before dispatch and omit it from the error so every transport has the
		// same fixed, bounded response.
		return marshal(errorResponse(nil, codeInvalidRequest, "request id exceeds size limit"))
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
		result, err := s.listTools(ctx, p)
		if err != nil {
			s.log.Warn("mcp authorization policy load failed", "tenant_id", p.TenantID, "error", err)
			return errorResponse(req.ID, codeUnavailable, "authorization policy is temporarily unavailable")
		}
		return resultResponse(req.ID, result)
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
func (s *Server) listTools(ctx context.Context, p *auth.Principal) (map[string]any, error) {
	rbacTools := make([]Tool, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		if !p.Has(t.Permission) {
			continue
		}
		rbacTools = append(rbacTools, t)
	}
	if len(rbacTools) == 0 {
		return map[string]any{"tools": []toolDescriptor{}}, nil
	}
	policies, err := s.loadPolicies(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	tools := make([]toolDescriptor, 0, len(rbacTools))
	for _, t := range rbacTools {
		if !auth.Authorize(p, t.Permission, policies, map[string]string{auth.ResourceTenantKey: p.TenantID}) {
			continue
		}
		tools = append(tools, toolDescriptor{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return map[string]any{"tools": tools}, nil
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
	emit := func(phase string, allowed bool, denial string) error {
		if s.audit == nil {
			return errCallAuditUnavailable
		}
		if err := s.audit(ctx, CallEvent{
			TenantID: p.TenantID,
			UserID:   p.UserID,
			Tool:     params.Name,
			Phase:    phase,
			Allowed:  allowed,
			Denial:   denial,
		}); err != nil {
			s.log.Warn("mcp durable call audit unavailable", "tenant_id", p.TenantID, "tool", params.Name, "error", err)
			return errCallAuditUnavailable
		}
		return nil
	}
	auditUnavailable := func() *rpcResponse {
		return errorResponse(req.ID, codeUnavailable, "durable audit is temporarily unavailable")
	}
	// Tenant boundary FIRST (in dispatch), then RBAC, then the tenant's ABAC
	// deny-override policies. A caller without the RBAC baseline never triggers a
	// policy lookup, and a policy-load failure never degrades to RBAC-only access.
	if !p.Has(t.Permission) {
		if err := emit(CallPhaseTerminal, false, "permission"); err != nil {
			return auditUnavailable()
		}
		return errorResponse(req.ID, codeForbidden, "missing permission: "+t.Permission)
	}
	policies, err := s.loadPolicies(ctx, p.TenantID)
	if err != nil {
		s.log.Warn("mcp authorization policy load failed", "tenant_id", p.TenantID, "tool", params.Name, "error", err)
		if err := emit(CallPhaseTerminal, false, "policy"); err != nil {
			return auditUnavailable()
		}
		return errorResponse(req.ID, codeUnavailable, "authorization policy is temporarily unavailable")
	}
	if !auth.Authorize(p, t.Permission, policies, map[string]string{auth.ResourceTenantKey: p.TenantID}) {
		if err := emit(CallPhaseTerminal, false, "permission"); err != nil {
			return auditUnavailable()
		}
		return errorResponse(req.ID, codeForbidden, "denied by an attribute policy: "+t.Permission)
	}
	if !s.limiter.allow(p.TenantID) {
		if err := emit(CallPhaseTerminal, false, "rate"); err != nil {
			return auditUnavailable()
		}
		return errorResponse(req.ID, codeRateLimited, "rate limit exceeded for tenant")
	}
	// AIRCA-001: the MCP caller is an EXTERNAL AI CLIENT — returning tool
	// output is tenant telemetry egressing the platform. The same per-tenant
	// consent that gates the remote RCA model gates this (default deny), and
	// the gate's redaction policy is applied to everything returned.
	if err := s.gate.Authorize(ctx, p.TenantID); err != nil {
		if auditErr := emit(CallPhaseTerminal, false, "consent"); auditErr != nil {
			return auditUnavailable()
		}
		return resultResponse(req.ID, toolResult(err.Error(), nil, true))
	}
	// Record the authorized call before invoking a tool. A failed immutable
	// append must never allow a read (or an RCA tool's nested remote dispatch).
	if err := emit(CallPhaseAdmission, true, ""); err != nil {
		return auditUnavailable()
	}
	out, err := t.Invoke(ctx, p, params.Arguments)
	if err != nil {
		// A tool error is returned as an isError tool result (MCP idiom) so the
		// model can react, but dependency error text is server-only: it can
		// contain DSNs, hostnames, schemas, or an attacker-sized response body.
		s.log.Warn("mcp tool invocation failed", "tenant_id", p.TenantID, "tool", params.Name, "error", err)
		if auditErr := emit(CallPhaseTerminal, false, terminalToolDenial(err)); auditErr != nil {
			return auditUnavailable()
		}
		return resultResponse(req.ID, toolResult("tool execution failed", nil, true))
	}
	res, rerr := s.redactedResult(p.TenantID, out)
	if rerr != nil {
		if auditErr := emit(CallPhaseTerminal, false, "result_encoding"); auditErr != nil {
			return auditUnavailable()
		}
		return errorResponse(req.ID, codeInternal, "tool result encoding failed")
	}
	// The result is now bounded and redacted but has not left the process.
	// Persist the external-egress receipt before returning it to either wire.
	if err := s.gate.Emit(ctx, ai.EgressEvent{
		TenantID: p.TenantID,
		Endpoint: "mcp-client",
		Model:    "mcp",
		Surface:  "mcp",
	}); err != nil {
		s.log.Warn("mcp durable egress audit unavailable", "tenant_id", p.TenantID, "tool", params.Name, "error", err)
		if auditErr := emit(CallPhaseTerminal, false, "egress_audit"); auditErr != nil {
			return auditUnavailable()
		}
		return auditUnavailable()
	}
	if err := emit(CallPhaseTerminal, true, ""); err != nil {
		return auditUnavailable()
	}
	return resultResponse(req.ID, res)
}

func terminalToolDenial(err error) string {
	switch {
	case errors.Is(err, fairness.ErrQueryConcurrency):
		return "fairness_concurrency"
	case errors.Is(err, fairness.ErrQueryBudget):
		return "fairness_budget"
	default:
		return "execution"
	}
}

func (s *Server) loadPolicies(ctx context.Context, tenantID string) ([]auth.Policy, error) {
	if s.policyLoader == nil {
		return nil, nil
	}
	return s.policyLoader(ctx, tenantID)
}

// redactedResult renders a tool's output ONCE through the gate's redaction
// (C8/AIRCA-002) and returns the MCP result carrying the redacted text and
// the redacted structured content — the un-redacted object never reaches
// the wire. Masking happens on the JSON encoding; tenant-scoped deterministic
// tokens keep the JSON valid and values correlatable only inside the tenant.
func (s *Server) redactedResult(tenantID string, out any) (map[string]any, error) {
	b, err := marshalBoundedJSON(out, maxMCPToolResultBytes, true)
	if err != nil {
		return nil, err
	}
	red := s.gate.RedactForTenant(string(b), tenantID)
	if len(red) > maxMCPToolResultBytes {
		return nil, errToolResultTooLarge
	}
	result := map[string]any{
		"content":           []map[string]any{{"type": "text", "text": red}},
		"structuredContent": json.RawMessage(red),
	}
	// The MCP result intentionally carries two representations. Bound their
	// combined serialized form too, not only the source object.
	if _, err := marshalBoundedJSON(result, maxMCPToolResultBytes, false); err != nil {
		return nil, err
	}
	return result, nil
}

type boundedJSONBuffer struct {
	bytes.Buffer
	max int
}

func (b *boundedJSONBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, errToolResultTooLarge
	}
	return b.Buffer.Write(p)
}

// validateJSONSourceBudget walks the source before encoding/json allocates its
// internal encode buffer. It caps both tenant-controlled scalar bytes and
// structural nodes. The walk itself is bounded: a wide container is refused
// from Len before its children are queued, and pointer cycles consume nodes
// until they hit the fixed ceiling.
func validateJSONSourceBudget(v any, maxSourceBytes int) error {
	if maxSourceBytes <= 0 {
		return errToolResultTooLarge
	}
	stack := []reflect.Value{reflect.ValueOf(v)}
	nodes, sourceBytes := 0, 0

	addBytes := func(n int) bool {
		if n < 0 || n > maxSourceBytes-sourceBytes {
			return false
		}
		sourceBytes += n
		return true
	}
	reserveChildren := func(n int) bool {
		return n >= 0 && n <= maxMCPToolResultNodes-nodes-len(stack)
	}

	for len(stack) > 0 {
		last := len(stack) - 1
		value := stack[last]
		stack = stack[:last]
		nodes++
		if nodes > maxMCPToolResultNodes || !value.IsValid() {
			if nodes > maxMCPToolResultNodes {
				return errToolResultTooLarge
			}
			continue
		}

		switch value.Kind() {
		case reflect.Interface, reflect.Pointer:
			if !value.IsNil() {
				if !reserveChildren(1) {
					return errToolResultTooLarge
				}
				stack = append(stack, value.Elem())
			}
		case reflect.String:
			if !addBytes(value.Len()) {
				return errToolResultTooLarge
			}
		case reflect.Slice:
			if value.IsNil() {
				continue
			}
			// encoding/json treats []byte (including json.RawMessage's source
			// representation) as one byte-bearing scalar, not N JSON nodes.
			if value.Type().Elem().Kind() == reflect.Uint8 {
				if !addBytes(value.Len()) {
					return errToolResultTooLarge
				}
				continue
			}
			fallthrough
		case reflect.Array:
			if !reserveChildren(value.Len()) {
				return errToolResultTooLarge
			}
			for i := value.Len() - 1; i >= 0; i-- {
				stack = append(stack, value.Index(i))
			}
		case reflect.Map:
			if value.IsNil() {
				continue
			}
			// Each entry contributes at least one key node and one value node.
			// Charge the keys now and reserve all values before MapRange can
			// grow the traversal stack.
			if !reserveChildren(2 * value.Len()) {
				return errToolResultTooLarge
			}
			nodes += value.Len()
			iter := value.MapRange()
			for iter.Next() {
				key := iter.Key()
				switch key.Kind() {
				case reflect.String:
					if !addBytes(key.Len()) {
						return errToolResultTooLarge
					}
				default:
					// Integer and TextMarshaler map keys are bounded by node
					// count; charge a conservative scalar rendering allowance.
					if !addBytes(64) {
						return errToolResultTooLarge
					}
				}
				stack = append(stack, iter.Value())
			}
		case reflect.Struct:
			typ := value.Type()
			if !reserveChildren(typ.NumField()) {
				return errToolResultTooLarge
			}
			fields := make([]int, 0, typ.NumField())
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" && !field.Anonymous {
					continue // ordinary unexported fields are not serialized
				}
				tagName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
				if tagName == "-" {
					continue
				}
				if tagName == "" {
					tagName = field.Name
				}
				if !addBytes(len(tagName)) {
					return errToolResultTooLarge
				}
				fields = append(fields, i)
			}
			if !reserveChildren(len(fields)) {
				return errToolResultTooLarge
			}
			for i := len(fields) - 1; i >= 0; i-- {
				stack = append(stack, value.Field(fields[i]))
			}
		}
	}
	return nil
}

func marshalBoundedJSON(v any, maxBytes int, indent bool) ([]byte, error) {
	if err := validateJSONSourceBudget(v, maxBytes); err != nil {
		return nil, err
	}
	dst := &boundedJSONBuffer{max: maxBytes}
	enc := json.NewEncoder(dst)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		if errors.Is(err, errToolResultTooLarge) {
			return nil, errToolResultTooLarge
		}
		return nil, err
	}
	// Encoder terminates a value with one newline; the existing wire format did
	// not, so remove only that framing byte after it participated in the bound.
	return bytes.TrimSuffix(dst.Bytes(), []byte{'\n'}), nil
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
