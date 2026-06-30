// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package change ingests, normalizes, and correlates heterogeneous change events
// (deploys, config/route/IaC changes, commits) so the AI RCA can answer "what
// changed?" (S29 · F39). Inbound webhooks are authenticated by a per-provider
// signature (HMAC) and tenant-scoped at the control-plane edge; this package is
// pure — it has no datastore, bus, or HTTP-server dependency, so the normalizers
// and the correlator are independently testable. Every event body is treated as
// UNTRUSTED input (CLAUDE.md §7 guardrail 12).
package change

import "time"

const grossFutureSkew = 15 * time.Minute

// Kind classifies a change so correlation + the UI can group by type.
type Kind string

const (
	KindDeploy  Kind = "deploy"  // a release/rollout reached an environment
	KindConfig  Kind = "config"  // a configuration change (network/device/app)
	KindRoute   Kind = "route"   // a routing/BGP change
	KindIaC     Kind = "iac"     // an infrastructure-as-code apply (Terraform/Atlantis)
	KindCommit  Kind = "commit"  // a VCS push/commit
	KindRelease Kind = "release" // a tagged release
	KindOther   Kind = "other"
)

// Event is the canonical, normalized change record — the single model every
// source (GitHub/GitLab/CI/IaC) is mapped onto. TenantID is always stamped from
// the verified webhook credential at ingest, NEVER taken from the (untrusted)
// payload. Target/Prefix anchor time+topology correlation to incidents.
type Event struct {
	ID         string            `json:"id,omitempty"`
	TenantID   string            `json:"tenant_id"`
	Source     string            `json:"source"` // provider name: "github" | "gitlab" | "generic"
	Kind       Kind              `json:"kind"`
	Title      string            `json:"title"`
	Summary    string            `json:"summary,omitempty"`
	Target     string            `json:"target,omitempty"` // affected host/service/IP (correlation anchor)
	Prefix     string            `json:"prefix,omitempty"` // affected CIDR (route changes)
	Actor      string            `json:"actor,omitempty"`  // who made the change
	Ref        string            `json:"ref,omitempty"`    // commit SHA / deploy id / tag
	URL        string            `json:"url,omitempty"`    // deep-link back to the source
	Attributes map[string]string `json:"attributes,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
	ReceivedAt time.Time         `json:"received_at,omitempty"`
}

// normalize fills defaults so a partially-populated event is still safe to store
// and correlate: a missing kind becomes "other"; a missing occurred-at is stamped
// now (the caller passes a clock for determinism). Grossly future-dated events are
// clamped to ingest time and annotated, so a bad source clock cannot poison later
// AI/RCA windows.
func (e *Event) normalize(source string, now time.Time) {
	if e.Source == "" {
		e.Source = source
	}
	if e.Kind == "" {
		e.Kind = KindOther
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = now
	}
	if e.OccurredAt.After(now.Add(grossFutureSkew)) {
		original := e.OccurredAt
		e.OccurredAt = now
		if e.Attributes == nil {
			e.Attributes = map[string]string{}
		}
		e.Attributes["occurred_at_clamped"] = "true"
		e.Attributes["original_occurred_at"] = original.UTC().Format(time.RFC3339Nano)
	}
}
