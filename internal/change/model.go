// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package change ingests, normalizes, and correlates heterogeneous change events
// (deploys, config/route/IaC changes, commits) so the AI RCA can answer "what
// changed?" (S29 · F39). Inbound webhooks are authenticated by a per-provider
// signature (HMAC) and tenant-scoped at the control-plane edge; this package is
// pure — it has no datastore, bus, or HTTP-server dependency, so the normalizers
// and the correlator are independently testable. Every event body is treated as
// UNTRUSTED input (docs/guardrails.md G7-12).
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

// ConfigReference points from a projected change event back to the exact pair
// of already-redacted device config snapshots that produced it. It deliberately
// contains hashes and identifiers only; config content remains available solely
// through the separately-authorized device archive API.
type ConfigReference struct {
	CurrentID       string `json:"current_id"`
	CurrentVersion  int    `json:"current_version"`
	CurrentHash     string `json:"current_hash"`
	PreviousID      string `json:"previous_id"`
	PreviousVersion int    `json:"previous_version"`
	PreviousHash    string `json:"previous_hash"`
}

// Event is the canonical, normalized change record — signed webhook inputs and
// safe read-time projections share this model. For ingested events, TenantID is
// always stamped from the verified credential, NEVER taken from the (untrusted)
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
	Config     *ConfigReference  `json:"config,omitempty"` // read-time device archive projection; never persisted
	OccurredAt time.Time         `json:"occurred_at"`
	ReceivedAt time.Time         `json:"received_at,omitempty"`
}

// normalize fills defaults so a partially-populated event is still safe to store
// and correlate: a missing kind becomes "other"; a missing occurred-at is stamped
// now (the caller passes a clock for determinism). Grossly future-dated events are
// clamped to ingest time and annotated, so a bad source clock cannot poison later
// AI/RCA windows.
// knownKind bounds a caller-supplied kind to the declared vocabulary: the
// generic webhook casts arbitrary strings into Kind, and an unbounded grouping
// enum would fragment the UI/correlation by every sender's private spelling.
func knownKind(k Kind) Kind {
	switch k {
	case KindDeploy, KindConfig, KindRoute, KindIaC, KindCommit, KindRelease, KindOther:
		return k
	default:
		return KindOther
	}
}

func (e *Event) normalize(source string, now time.Time) {
	if e.Source == "" {
		e.Source = source
	}
	if e.Kind == "" {
		e.Kind = KindOther
	}
	e.Kind = knownKind(e.Kind)
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
