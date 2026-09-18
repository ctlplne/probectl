// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/lifecycle"
	"github.com/ctlplne/probectl/internal/store"
)

// Fleet health uses the same five-minute heartbeat promise as rollout
// verification. One clock and one definition prevents an agent from appearing
// healthy in Admin while the rollout state machine correctly treats it as dark.
const fleetHeartbeatSLO = 5 * time.Minute

// DPR-176: rotation is meant to happen well inside an SVID's lifetime, so an
// identity still alive at this fraction of its window has already missed the
// renewals it should have made. Expressed as a FRACTION rather than a fixed
// number of hours because SVID lifetimes are a deployment choice: the same
// warning has to mean the same thing for a one-hour identity and a one-day one.
const fleetIdentityRenewalFraction = 0.75

type fleetSafeAction struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
	Href   string `json:"href"`
}

// fleetAgentView is the tenant registry row plus operator-facing, derived
// health. It contains no command, artifact URL, executable, or mutation
// payload: the only next action is a read-only review of evidence and the
// human-gated rollout runbook.
type fleetAgentView struct {
	store.Agent
	HeartbeatAgeSeconds *int64          `json:"heartbeat_age_seconds,omitempty"`
	HeartbeatState      string          `json:"heartbeat_state"`
	HeartbeatReason     string          `json:"heartbeat_reason"`
	VersionState        string          `json:"version_state"`
	VersionReason       string          `json:"version_reason"`
	IdentityExpiresAt   *time.Time      `json:"identity_expires_at,omitempty"`
	IdentityState       string          `json:"identity_state"`
	IdentityReason      string          `json:"identity_reason"`
	ReadinessState      string          `json:"readiness_state"`
	ReadinessReason     string          `json:"readiness_reason"`
	RolloutID           string          `json:"rollout_id,omitempty"`
	RolloutTarget       string          `json:"rollout_target,omitempty"`
	RolloutCohort       string          `json:"rollout_cohort,omitempty"`
	RolloutState        string          `json:"rollout_state,omitempty"`
	RolloutHalted       bool            `json:"rollout_halted"`
	RolloutHaltReason   string          `json:"rollout_halt_reason,omitempty"`
	LastFailure         string          `json:"last_failure"`
	NextSafeAction      fleetSafeAction `json:"next_safe_action"`
}

// buildFleetAgentViews joins only rows already selected inside the caller's
// RLS transaction. The newest rollout containing an agent wins, matching the
// rollout list's newest-first operator view. This function has no datastore
// access of its own, which makes the precedence and fail-closed join easy to
// test without weakening the storage boundary.
func buildFleetAgentViews(rows []store.Agent, rollouts []store.RolloutRecord, identities map[string]store.AgentIdentityWindow, controlVersion string, now time.Time) ([]fleetAgentView, error) {
	views := make([]fleetAgentView, len(rows))
	byID := make(map[string]*fleetAgentView, len(rows))
	for i := range rows {
		id, ok := identities[rows[i].ID]
		var window *store.AgentIdentityWindow
		if ok {
			window = &id
		}
		views[i] = newFleetAgentView(rows[i], window, controlVersion, now)
		byID[rows[i].ID] = &views[i]
	}

	assigned := make(map[string]bool, len(rows))
	for i := range rollouts {
		plan, err := decodeRolloutPlan(&rollouts[i])
		if err != nil {
			return nil, fmt.Errorf("decode rollout %s for fleet health: %w", rollouts[i].ID, err)
		}
		for _, wave := range plan.Waves {
			for _, id := range wave.AgentIDs {
				view, ok := byID[id]
				if !ok || assigned[id] {
					continue
				}
				assigned[id] = true
				view.RolloutID = rollouts[i].ID
				view.RolloutTarget = plan.Target.Version
				view.RolloutCohort = string(wave.Cohort)
				view.RolloutState = string(wave.Status)
				view.RolloutHalted = plan.Halted
				view.RolloutHaltReason = plan.HaltReason
				if plan.Halted {
					view.RolloutState = "halted"
					view.LastFailure = plan.HaltReason
					view.NextSafeAction = safeAction("review_halted_rollout", "Review halted rollout", "A human must review the failure, rollback if needed, and record a remediation note before resume.")
				} else if wave.Status == agent.WaveApplying {
					view.NextSafeAction = safeAction("verify_rollout_wave", "Review rollout health gate", "Confirm the signed target and fresh registry heartbeat before a human advances another cohort.")
				}
			}
		}
	}

	return views, nil
}

func newFleetAgentView(row store.Agent, identity *store.AgentIdentityWindow, controlVersion string, now time.Time) fleetAgentView {
	view := fleetAgentView{Agent: row, LastFailure: ""}
	view.IdentityState, view.IdentityReason = fleetIdentityState(identity, now)
	if identity != nil {
		expires := identity.NotAfter
		view.IdentityExpiresAt = &expires
	}

	switch {
	case row.LastSeenAt == nil:
		view.HeartbeatState = "never_seen"
		view.HeartbeatReason = "Agent has not completed an authenticated heartbeat."
	case row.Status == "offline":
		age := heartbeatAgeSeconds(now, *row.LastSeenAt)
		view.HeartbeatAgeSeconds = &age
		view.HeartbeatState = "stale"
		view.HeartbeatReason = "Agent is marked offline; inspect its last authenticated heartbeat."
	case now.Sub(*row.LastSeenAt) > fleetHeartbeatSLO:
		age := heartbeatAgeSeconds(now, *row.LastSeenAt)
		view.HeartbeatAgeSeconds = &age
		view.HeartbeatState = "stale"
		view.HeartbeatReason = fmt.Sprintf("Last authenticated heartbeat is older than the %s health gate.", fleetHeartbeatSLO)
	default:
		age := heartbeatAgeSeconds(now, *row.LastSeenAt)
		view.HeartbeatAgeSeconds = &age
		view.HeartbeatState = "ready"
		view.HeartbeatReason = "Authenticated heartbeat is inside the five-minute health gate."
	}

	view.VersionState, view.VersionReason = fleetVersionState(controlVersion, row.AgentVersion)

	switch {
	// An expired identity is checked BEFORE the heartbeat, because it is the
	// cause the heartbeat is only a symptom of: the agent goes quiet, and
	// "inspect the transport" sends the operator to the wrong place.
	case view.IdentityState == "expired":
		view.ReadinessState = "identity_expired"
		view.ReadinessReason = view.IdentityReason
		view.LastFailure = view.IdentityReason
		view.NextSafeAction = safeAction("reenroll_identity", "Re-enroll this agent", "An expired SVID cannot rotate itself: mint a join token and enroll the agent again. Nothing is changed for you.")
	case view.HeartbeatState == "never_seen":
		view.ReadinessState = "never_connected"
		view.ReadinessReason = view.HeartbeatReason
		view.LastFailure = view.HeartbeatReason
		view.NextSafeAction = safeAction("inspect_heartbeat", "Inspect enrollment and heartbeat", "Review mTLS enrollment and transport evidence; this action does not reconnect or update the agent.")
	case view.HeartbeatState == "stale":
		view.ReadinessState = "stale"
		view.ReadinessReason = view.HeartbeatReason
		view.LastFailure = view.HeartbeatReason
		view.NextSafeAction = safeAction("inspect_heartbeat", "Inspect stale heartbeat", "Review transport and agent logs before any human-approved rollout action.")
	case len(row.Capabilities) == 0:
		view.ReadinessState = "unsupported_capability"
		view.ReadinessReason = "Agent reported no supported telemetry capabilities."
		view.LastFailure = view.ReadinessReason
		view.NextSafeAction = safeAction("review_capabilities", "Review capability enrollment", "Compare the enrolled binary and configuration with the intended telemetry plane.")
	case view.VersionState == "unsupported" || view.VersionState == "supported_skew":
		view.ReadinessState = "version_skew"
		view.ReadinessReason = view.VersionReason
		if view.VersionState == "unsupported" {
			view.LastFailure = view.VersionReason
		}
		view.NextSafeAction = safeAction("review_staged_rollout", "Review staged rollout", "A human may plan a signed, cohort-gated rollout or rollback using the external orchestrator.")
	case view.IdentityState == "renewal_overdue":
		view.ReadinessState = "identity_renewal_overdue"
		view.ReadinessReason = view.IdentityReason
		view.LastFailure = view.IdentityReason
		view.NextSafeAction = safeAction("inspect_identity", "Inspect identity rotation", "Check that the agent can reach the control plane's enrollment endpoint; an identity that stops rotating ends as an agent that never returns.")
	default:
		view.ReadinessState = "ready"
		view.ReadinessReason = "Heartbeat, version policy, reported capabilities, and identity lifetime are ready."
		view.NextSafeAction = safeAction("inspect_evidence", "Inspect agent evidence", "Review the tenant-scoped registry evidence; no fleet change is performed.")
	}
	return view
}

// fleetIdentityState reads the agent's own credential window. "unknown" is a
// real answer and says so: an agent enrolled before this deployment recorded
// issuance has no window to read, and guessing "current" for it would be the
// confident-verdict-over-unmeasured-evidence bug this project exists to stop.
func fleetIdentityState(identity *store.AgentIdentityWindow, now time.Time) (string, string) {
	if identity == nil || identity.NotAfter.IsZero() {
		return "unknown", "No issued identity is recorded for this agent; its certificate lifetime cannot be read here."
	}
	if !now.Before(identity.NotAfter) {
		return "expired", fmt.Sprintf("Agent identity expired %s. An expired SVID cannot rotate itself; the agent must enroll again.",
			identity.NotAfter.UTC().Format(time.RFC3339))
	}
	lifetime := identity.NotAfter.Sub(identity.IssuedAt)
	if lifetime > 0 {
		elapsed := now.Sub(identity.IssuedAt)
		if float64(elapsed) >= fleetIdentityRenewalFraction*float64(lifetime) {
			return "renewal_overdue", fmt.Sprintf(
				"Agent identity expires %s and is past %d%% of its lifetime with no rotation recorded.",
				identity.NotAfter.UTC().Format(time.RFC3339), int(fleetIdentityRenewalFraction*100))
		}
	}
	return "current", fmt.Sprintf("Agent identity is valid until %s.", identity.NotAfter.UTC().Format(time.RFC3339))
}

func fleetVersionState(controlVersion, agentVersion string) (string, string) {
	if agentVersion == "" {
		return "unknown", "Agent has not reported a version."
	}
	cv, cerr := lifecycle.Parse(controlVersion)
	av, aerr := lifecycle.Parse(agentVersion)
	if cerr != nil || cv.Dev {
		return "unknown", "Control-plane build is unpinned; version skew cannot be evaluated."
	}
	if aerr != nil {
		return "unsupported", fmt.Sprintf("Agent version %q is not a valid semantic version.", agentVersion)
	}
	if ok, reason := lifecycle.DefaultPolicy().Check(controlVersion, agentVersion); !ok {
		return "unsupported", reason
	}
	if cv.Compare(av) != 0 {
		return "supported_skew", fmt.Sprintf("Agent %s is inside the supported N/N-1 window but differs from control %s.", agentVersion, controlVersion)
	}
	return "current", "Agent matches the control-plane version."
}

func heartbeatAgeSeconds(now, seen time.Time) int64 {
	if seen.After(now) {
		return 0
	}
	return int64(now.Sub(seen).Round(time.Second) / time.Second)
}

func safeAction(kind, label, reason string) fleetSafeAction {
	return fleetSafeAction{Kind: kind, Label: label, Reason: reason, Href: "/docs/api#rollouts"}
}
