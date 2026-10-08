// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

// Staged fleet rollout (U-031). The control plane PLANS waves from the agent
// registry and VERIFIES each wave back out of the registry; APPLYING a wave
// is the external orchestrator's job (helm upgrade of the U-016 DaemonSet
// chart, or deploy/agent/install.sh on VMs) using C6-SIGNED artifacts only.
// There is deliberately NO agent self-update channel — update authority
// stays outside the data plane (preserved strength ST-04; an agent that can
// fetch and exec new code is a fleet-wide RCE primitive).
//
// The flow (docs/ops/fleet-rollout.md):
//
//	verify artifact (cosign) → PlanRollout → for each wave:
//	    Advance → orchestrator applies → Verify (registry: target version +
//	    fresh heartbeat per member) → next wave
//
// Verification failure HALTS the rollout: no later wave can start until an
// operator explicitly Resumes after remediation. The plan refuses targets
// that would break the N/N-1 skew gate, and refuses artifacts whose Method does
// not name a RECOGNIZED signature verification — "none" or any unrecognized
// string is not a verification, so recording it as "verified" is refused at
// plan time (RTO-24; docs/guardrails.md G7-12). A wave completes only when
// every member reports the exact DEPLOYED DIGEST, never the self-reported
// version alone: the version is a label an old or tampered binary can still
// carry, so version-only convergence is not proof the signed artifact landed
// (RTO-24; docs/guardrails.md G7-8).

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/lifecycle"
)

// FleetAgent is the registry's view of one agent (the subset the rollout
// needs); callers map store rows into it.
type FleetAgent struct {
	ID       string
	TenantID string
	Version  string
	// Digest is the exact artifact digest the agent reports it is running
	// (sha256:<hex>). Verify requires it to equal the rollout's deployed digest
	// before completing a wave — the self-reported Version is only a label, and
	// an old or tampered binary can carry the target version while running a
	// different image (RTO-24; docs/guardrails.md G7-8). Empty means the agent
	// has not reported a deployed digest, which Verify treats as unverified
	// (fail closed), never as "on the target".
	Digest   string
	LastSeen time.Time
}

// digestRE is the only artifact digest shape a rollout accepts: the exact
// image/binary digest the orchestrator deploys (DPR-099; a doubled prefix or
// a truncated hash used to plan a rollout nobody could verify).
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// VerifiedArtifact records the signed artifact a rollout deploys and WHO
// verified its signature HOW (C6 — cosign keyless; see
// docs/ops/verify-artifacts.md). Planning refuses an incomplete record:
// unsigned or unattested artifacts never enter the fleet.
type VerifiedArtifact struct {
	Version    string // e.g. "v0.2.1"
	Digest     string // the exact image/binary digest the orchestrator deploys
	Method     string // e.g. "cosign verify ghcr.io/...@sha256:... --certificate-identity-regexp ..."
	VerifiedBy string // operator identity (audit trail)
}

// recognizedVerifiers are the signature-verification tools a rollout accepts in
// its Method record (C6; docs/ops/verify-artifacts.md). A Method naming none of
// them — "none", a blank, or any unrecognized string — is not a verification,
// so recording it as "verified" is refused at plan time rather than trusted
// (RTO-24; docs/guardrails.md G7-12: missing signature → fail closed).
var recognizedVerifiers = []string{"cosign"}

// methodVerifies reports whether Method names a real signature verification. It
// is deliberately a positive allowlist (fail closed): an unrecognized method —
// crucially "none" — is NOT a verification. The method is the command that was
// run ("cosign verify …", "cosign verify-blob …"), so its FIRST word must be a
// recognized verifier: a method that merely mentions one ("skipped cosign",
// "no cosign", "cosign-less") is refused. Extend the allowlist in one place
// when a new verifier is adopted.
func methodVerifies(method string) bool {
	fields := strings.Fields(strings.ToLower(method))
	if len(fields) == 0 {
		return false
	}
	for _, v := range recognizedVerifiers {
		if fields[0] == v {
			return true
		}
	}
	return false
}

func (a VerifiedArtifact) validate() error {
	switch {
	case a.Version == "":
		return fmt.Errorf("agent: rollout artifact needs a version")
	case a.Digest == "":
		return fmt.Errorf("agent: rollout artifact needs the exact digest being deployed (U-006)")
	case !digestRE.MatchString(a.Digest):
		return fmt.Errorf("agent: rollout artifact digest must be sha256:<64 hex> (got %q)", a.Digest)
	case a.Method == "":
		return fmt.Errorf("agent: rollout artifact needs the signature-verification method (C6 — how was cosign run?)")
	case !methodVerifies(a.Method):
		// RTO-24: "none"/unknown is not a verification. Accepting it would let a
		// rollout claim "verified" without any — fail closed (docs/guardrails.md G7-12).
		return fmt.Errorf("agent: rollout verify_method %q is not a recognized signature verification — record how the artifact was cosign-verified; %q or an unverifiable method is refused (C6; docs/guardrails.md G7-12)", a.Method, "none")
	case a.VerifiedBy == "":
		return fmt.Errorf("agent: rollout artifact needs the verifier's identity (who ran the verification?)")
	}
	return nil
}

// WaveStatus is one wave's lifecycle: pending → applying → complete, or
// halted (verification failed; the whole rollout stops).
type WaveStatus string

const (
	WavePending  WaveStatus = "pending"
	WaveApplying WaveStatus = "applying"
	WaveComplete WaveStatus = "complete"
	WaveHalted   WaveStatus = "halted"
)

// Wave is one ring of the fleet, fixed at plan time.
type Wave struct {
	Cohort    lifecycle.Cohort
	AgentIDs  []string
	Status    WaveStatus
	AppliedAt time.Time
}

// RolloutPlan is the wave state machine for one target version.
type RolloutPlan struct {
	Target VerifiedArtifact
	Waves  []Wave

	// VerifyWindow is how long a wave gets after Advance before stragglers
	// halt the rollout; HeartbeatSLO bounds how stale a member's registry
	// heartbeat may be and still count as alive.
	VerifyWindow time.Duration
	HeartbeatSLO time.Duration

	Halted     bool
	HaltReason string
	// SkippedOffline lists the agents left out at planning time because they
	// were offline or had never connected (DPR-099); they take the target on
	// the next rollout once they are back.
	SkippedOffline []string `json:"skipped_offline,omitempty"`
	// Stragglers is the last verification's list of agents in the applying
	// wave that have not yet reported the target version with a fresh
	// heartbeat (DPR-099) — the operator's worklist while the window runs.
	Stragglers []string `json:"stragglers,omitempty"`
}

const (
	defaultVerifyWindow = 15 * time.Minute
	defaultHeartbeatSLO = 5 * time.Minute
)

// PlanRolloutAt partitions the live fleet into deterministic waves (the
// lifecycle cohorts: canary → early → main) for target. It fails closed on an
// unattested artifact, on a target that violates the version-skew policy
// against the control plane, and on an empty fleet; agents already running the
// target are excluded because there is nothing to apply to them.
//
// Planning happens as of now (DPR-099): an agent whose last heartbeat is older
// than the heartbeat SLO — offline before the rollout started, or never
// connected — is left out of the waves and listed in SkippedOffline instead of
// blocking a wave it can never verify. The zero time plans every agent (the
// pre-DPR-099 behavior, used by tests that model no clock).
func PlanRolloutAt(fleet []FleetAgent, target VerifiedArtifact, split lifecycle.Split, controlVersion string, pol lifecycle.Policy, now time.Time) (*RolloutPlan, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	var skipped []string
	if !now.IsZero() {
		live := fleet[:0:0]
		for _, a := range fleet {
			if a.LastSeen.IsZero() || now.Sub(a.LastSeen) > defaultHeartbeatSLO {
				if a.ID != "" && a.Version != target.Version {
					skipped = append(skipped, a.ID)
				}
				continue
			}
			live = append(live, a)
		}
		fleet = live
		sort.Strings(skipped)
	}
	if ok, reason := pol.Check(controlVersion, target.Version); !ok {
		return nil, fmt.Errorf("agent: rollout target %s would break the version-skew gate: %s", target.Version, reason)
	}

	byCohort := map[lifecycle.Cohort][]string{}
	pending := 0
	for _, a := range fleet {
		if a.ID == "" || a.Version == target.Version {
			continue
		}
		c := lifecycle.CohortOf(a.ID, split)
		byCohort[c] = append(byCohort[c], a.ID)
		pending++
	}
	if pending == 0 {
		if len(skipped) > 0 {
			return nil, fmt.Errorf("agent: nothing to roll out — the %d agent(s) below %s were all offline at planning time (%s)", len(skipped), target.Version, strings.Join(skipped, ", "))
		}
		return nil, fmt.Errorf("agent: nothing to roll out — no live agents below %s", target.Version)
	}

	p := &RolloutPlan{Target: target, VerifyWindow: defaultVerifyWindow, HeartbeatSLO: defaultHeartbeatSLO, SkippedOffline: skipped}
	for _, c := range []lifecycle.Cohort{lifecycle.CohortCanary, lifecycle.CohortEarly, lifecycle.CohortMain} {
		ids := byCohort[c]
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		p.Waves = append(p.Waves, Wave{Cohort: c, AgentIDs: ids, Status: WavePending})
	}
	return p, nil
}

// CurrentWave returns the wave in flight or up next (nil when the rollout is
// complete or halted).
func (p *RolloutPlan) CurrentWave() *Wave {
	if p.Halted {
		return nil
	}
	for i := range p.Waves {
		if p.Waves[i].Status != WaveComplete {
			return &p.Waves[i]
		}
	}
	return nil
}

// Done reports whether every wave verified complete.
func (p *RolloutPlan) Done() bool {
	for i := range p.Waves {
		if p.Waves[i].Status != WaveComplete {
			return false
		}
	}
	return !p.Halted
}

// Advance releases the next pending wave to the external orchestrator and
// returns it (the orchestrator then upgrades exactly those agents with the
// verified artifact). It refuses while halted, while a wave is still
// applying (waves never overlap or skip), and when nothing is left.
func (p *RolloutPlan) Advance(now time.Time) (*Wave, error) {
	if p.Halted {
		return nil, fmt.Errorf("agent: rollout is HALTED (%s) — remediate, then Resume", p.HaltReason)
	}
	w := p.CurrentWave()
	if w == nil {
		return nil, fmt.Errorf("agent: rollout already complete")
	}
	if w.Status == WaveApplying {
		return nil, fmt.Errorf("agent: wave %q is still applying — verify it before advancing (waves never overlap)", w.Cohort)
	}
	w.Status = WaveApplying
	w.AppliedAt = now
	return w, nil
}

// Verify checks the applying wave against a fresh registry snapshot: every
// member must report the exact DEPLOYED DIGEST (not just the target version)
// with a heartbeat within HeartbeatSLO. All good → the wave completes.
// Stragglers inside VerifyWindow → still converging (no state change).
// Stragglers after VerifyWindow — wrong version, wrong/absent artifact digest,
// gone dark, or missing from the registry — HALT the whole rollout.
//
// The digest gate is the point of verification (RTO-24): the self-reported
// version is a label an old or tampered binary can carry unchanged (e.g. a
// same-tag rebuild with different content), so completing on the version alone
// would let "verified" mean nothing. A member that has not reported the
// deployed digest is treated as unverified, never as converged (fail closed,
// docs/guardrails.md G7-8).
func (p *RolloutPlan) Verify(fleet []FleetAgent, now time.Time) (complete bool, err error) {
	if p.Halted {
		return false, fmt.Errorf("agent: rollout is HALTED (%s)", p.HaltReason)
	}
	w := p.CurrentWave()
	if w == nil || w.Status != WaveApplying {
		return false, fmt.Errorf("agent: no wave is applying — Advance first")
	}

	byID := make(map[string]FleetAgent, len(fleet))
	for _, a := range fleet {
		byID[a.ID] = a
	}
	var stragglers []string
	for _, id := range w.AgentIDs {
		a, ok := byID[id]
		switch {
		case !ok:
			stragglers = append(stragglers, id+" (missing from the registry)")
		case a.Version != p.Target.Version:
			stragglers = append(stragglers, fmt.Sprintf("%s (still on %s)", id, a.Version))
		case a.Digest != p.Target.Digest:
			// RTO-24: right version label, wrong (or no) deployed artifact — the
			// agent has NOT taken the signed digest the operator verified. Never
			// complete on the version string alone (docs/guardrails.md G7-8).
			stragglers = append(stragglers, fmt.Sprintf("%s (%s)", id, digestStragglerReason(a.Digest, p.Target.Digest)))
		case now.Sub(a.LastSeen) > p.HeartbeatSLO:
			stragglers = append(stragglers, fmt.Sprintf("%s (no heartbeat for %s — dark after upgrade?)", id, now.Sub(a.LastSeen).Round(time.Second)))
		}
	}
	p.Stragglers = stragglers
	if len(stragglers) == 0 {
		w.Status = WaveComplete
		return true, nil
	}
	if now.Sub(w.AppliedAt) > p.VerifyWindow {
		w.Status = WaveHalted
		p.Halted = true
		p.HaltReason = fmt.Sprintf("wave %q failed verification after %s: %s",
			w.Cohort, p.VerifyWindow, strings.Join(stragglers, "; "))
		return false, fmt.Errorf("agent: ROLLOUT HALTED — %s", p.HaltReason)
	}
	return false, nil // inside the window: keep converging, verify again
}

// digestStragglerReason explains why a member on the target version is still a
// straggler: it has not reported the deployed artifact digest at all, or it
// reports a different one (RTO-24). An empty digest is the common case before
// the agent reports what it is actually running — unverified, never "converged".
func digestStragglerReason(got, want string) string {
	if strings.TrimSpace(got) == "" {
		return "has not reported the deployed artifact digest"
	}
	return fmt.Sprintf("reports digest %s, not the deployed %s", got, want)
}

// Halt stops the rollout immediately on operator command (OPS-002): the
// current applying wave is marked halted and no wave advances until Resume.
// Idempotent — halting an already-halted rollout keeps the first reason.
func (p *RolloutPlan) Halt(reason string) {
	if p.Halted {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "halted by operator"
	}
	for i := range p.Waves {
		if p.Waves[i].Status == WaveApplying {
			p.Waves[i].Status = WaveHalted
		}
	}
	p.Halted = true
	p.HaltReason = reason
}

// Resume clears a halt after explicit operator remediation (recorded in
// reason) and returns the failed wave to applying with a fresh window. It is
// the ONLY way past a halt — a halted rollout never advances on its own.
func (p *RolloutPlan) Resume(reason string, now time.Time) error {
	if !p.Halted {
		return fmt.Errorf("agent: rollout is not halted")
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("agent: Resume requires the operator's remediation note")
	}
	for i := range p.Waves {
		if p.Waves[i].Status == WaveHalted {
			p.Waves[i].Status = WaveApplying
			p.Waves[i].AppliedAt = now
		}
	}
	p.Halted = false
	p.HaltReason = ""
	return nil
}

// Progress renders a one-line operator summary.
func (p *RolloutPlan) Progress() string {
	parts := make([]string, 0, len(p.Waves))
	for i := range p.Waves {
		w := &p.Waves[i]
		parts = append(parts, fmt.Sprintf("%s[%d]=%s", w.Cohort, len(w.AgentIDs), w.Status))
	}
	s := fmt.Sprintf("rollout to %s (%s): %s", p.Target.Version, p.Target.Digest, strings.Join(parts, " "))
	if p.Halted {
		s += " — HALTED: " + p.HaltReason
	}
	return s
}
