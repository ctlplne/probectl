// SPDX-License-Identifier: LicenseRef-probectl-TBD

package notify

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Inbound verification headers. An operator configures their ITSM/on-call
// outbound integration to include one over TLS:
//   - X-Probectl-Signature: sha256=<hex HMAC of the raw body under the secret>, or
//   - X-Probectl-Token: <the shared secret> (constant-time compared).
const (
	InboundSignatureHeader = "X-Probectl-Signature"
	InboundTokenHeader     = "X-Probectl-Token"
)

// VerifyInbound authenticates an inbound provider webhook against the connector's
// secret. It accepts a valid HMAC signature OR a matching shared token, and fails
// closed (false) when the secret is empty or neither proof is present/valid — so
// a forged or unsigned delivery is rejected before it can change incident state.
func VerifyInbound(secret string, body []byte, h http.Header) bool {
	if secret == "" {
		return false
	}
	if sig := h.Get(InboundSignatureHeader); sig != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
		if err != nil {
			return false
		}
		return crypto.Verify([]byte(secret), body, raw)
	}
	if tok := h.Get(InboundTokenHeader); tok != "" {
		return crypto.ConstantTimeEqual([]byte(tok), []byte(secret))
	}
	return false
}

// InboundResult is the incident-relevant state an inbound webhook conveys.
type InboundResult struct {
	ExternalRef string // matches the ref stored when the object was opened
	Resolved    bool   // the external object was resolved/closed
	Acked       bool   // the external object was acknowledged
}

// ParseInbound extracts the external ref + state from a provider's inbound
// webhook body. ServiceNow + Jira native shapes are understood directly; every
// provider (incl. PagerDuty/Opsgenie) also supports the portable contract
// {"external_ref": "...", "status": "resolved|acknowledged|open"}. ok is false
// when the body can't be understood (caller returns 400 / no-op).
func ParseInbound(provider string, body []byte) (InboundResult, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "servicenow":
		if r, ok := parseServiceNowInbound(body); ok {
			return r, true
		}
	case "jira":
		if r, ok := parseJiraInbound(body); ok {
			return r, true
		}
	}
	return parseGenericInbound(body)
}

// parseGenericInbound reads the portable {"external_ref","status"} contract.
func parseGenericInbound(body []byte) (InboundResult, bool) {
	var p struct {
		ExternalRef string `json:"external_ref"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return InboundResult{}, false
	}
	ref := strings.TrimSpace(p.ExternalRef)
	if ref == "" {
		return InboundResult{}, false
	}
	st := strings.ToLower(strings.TrimSpace(p.Status))
	return InboundResult{
		ExternalRef: ref,
		Resolved:    st == "resolved" || st == "closed",
		Acked:       st == "acknowledged" || st == "ack",
	}, true
}

// parseServiceNowInbound reads a ServiceNow Business-Rule POST
// ({"sys_id","number","state"}); state 6/7 (or "resolved"/"closed") is resolved.
func parseServiceNowInbound(body []byte) (InboundResult, bool) {
	var p struct {
		SysID  string `json:"sys_id"`
		Number string `json:"number"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return InboundResult{}, false
	}
	ref := strings.TrimSpace(p.SysID)
	if ref == "" {
		return InboundResult{}, false
	}
	switch strings.ToLower(strings.TrimSpace(p.State)) {
	case "6", "7", "resolved", "closed":
		return InboundResult{ExternalRef: ref, Resolved: true}, true
	default:
		return InboundResult{ExternalRef: ref}, true
	}
}

// parseJiraInbound reads a Jira issue webhook; a "done" status category is
// resolved.
func parseJiraInbound(body []byte) (InboundResult, bool) {
	var p struct {
		Issue struct {
			Key    string `json:"key"`
			Fields struct {
				Status struct {
					StatusCategory struct {
						Key string `json:"key"`
					} `json:"statusCategory"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issue"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Issue.Key == "" {
		return InboundResult{}, false
	}
	ref := strings.TrimSpace(p.Issue.Key)
	if ref == "" {
		return InboundResult{}, false
	}
	return InboundResult{
		ExternalRef: ref,
		Resolved:    strings.EqualFold(p.Issue.Fields.Status.StatusCategory.Key, "done"),
	}, true
}
