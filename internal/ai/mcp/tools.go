package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// Tool is one MCP tool: its name, description, JSON-Schema input, the RBAC
// permission a caller must hold, and its invoke function (which calls the
// backend). The schemas are the documented contract.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Permission  string
	Invoke      func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error)
}

// Permission keys gating each tool (mirror internal/ai + internal/control). The
// tenant boundary is enforced before any of these.
const (
	permTestRead     = "test.read"
	permEventsRead   = "events.read"
	permIncidentRead = "incident.read"
	permAIQuery      = "ai.query"
)

// buildTools returns the S25 read-only tool catalog. Other sprints append tools
// (security/cost/SLO/topology); write/remediation tools are deferred to S-EE5.
func buildTools(b Backend) []Tool {
	return []Tool{
		{
			Name:        "list_tests",
			Permission:  permTestRead,
			Description: "List the synthetic tests/canaries configured in the caller's tenant.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, _ json.RawMessage) (any, error) {
				return b.ListTests(ctx, p)
			},
		},
		{
			Name:        "get_path",
			Permission:  permTestRead,
			Description: "Get the most recently discovered network path to a target (hops, per-hop loss/latency, MPLS).",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"host, IP, or URL the path was measured to"}},"required":["target"],"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				var a struct {
					Target string `json:"target"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				if strings.TrimSpace(a.Target) == "" {
					return nil, argErr("target is required")
				}
				return b.GetPath(ctx, p, a.Target)
			},
		},
		{
			Name:        "get_bgp_events",
			Permission:  permEventsRead,
			Description: "Query recent BGP/routing events (announcements, withdrawals, possible hijacks) for a prefix or origin AS.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"prefix":{"type":"string","description":"CIDR to filter by"},"asn":{"type":"string","description":"origin AS number"},"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				var a struct {
					Prefix string `json:"prefix"`
					ASN    string `json:"asn"`
					Limit  int    `json:"limit"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				return b.GetBGPEvents(ctx, p, a.Prefix, a.ASN, a.Limit)
			},
		},
		{
			Name:        "query_flows",
			Permission:  permEventsRead,
			Description: "Query network flow/service-map records (eBPF) by service or source/destination.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"service":{"type":"string"},"src":{"type":"string"},"dst":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				var a struct {
					Service string `json:"service"`
					Src     string `json:"src"`
					Dst     string `json:"dst"`
					Limit   int    `json:"limit"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				return b.QueryFlows(ctx, p, a.Service, a.Src, a.Dst, a.Limit)
			},
		},
		{
			Name:        "get_incident",
			Permission:  permIncidentRead,
			Description: "Get one incident with its full cross-plane signal timeline.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"incident id"}},"required":["id"],"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				id, err := idArg(args)
				if err != nil {
					return nil, err
				}
				return b.GetIncident(ctx, p, id)
			},
		},
		{
			Name:        "correlate_incident",
			Permission:  permIncidentRead,
			Description: "Summarize an incident's cross-plane correlation: which planes contributed and the signal timeline.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"incident id"}},"required":["id"],"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				id, err := idArg(args)
				if err != nil {
					return nil, err
				}
				return b.CorrelateIncident(ctx, p, id)
			},
		},
		{
			Name:        "explain_degradation",
			Permission:  permAIQuery,
			Description: "Run root-cause analysis on a natural-language question (\"why is X slow for Y?\"), returning a cited, RBAC-scoped root cause.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"question":{"type":"string"},"subject":{"type":"object","additionalProperties":{"type":"string"},"description":"optional subject pins: target, prefix, node"}},"required":["question"],"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, args json.RawMessage) (any, error) {
				var a struct {
					Question string            `json:"question"`
					Subject  map[string]string `json:"subject"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				if strings.TrimSpace(a.Question) == "" {
					return nil, argErr("question is required")
				}
				return b.ExplainDegradation(ctx, p, a.Question, a.Subject)
			},
		},
	}
}

func decodeArgs(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return argErr(err.Error())
	}
	return nil
}

func idArg(raw json.RawMessage) (string, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return "", err
	}
	if strings.TrimSpace(a.ID) == "" {
		return "", argErr("id is required")
	}
	return a.ID, nil
}

func argErr(msg string) error { return fmt.Errorf("invalid arguments: %s", msg) }
