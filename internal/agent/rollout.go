// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
// that would break the N/N-1 skew gate, and refuses artifacts without a
// recorded signature verification.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
)

// FleetAgent is the registry's view of one agent (the subset the rollout
// needs); callers map store rows into it.
type FleetAgent struct {
	ID       string
	TenantID string
	Version  string
	LastSeen time.Time
}

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

func (a VerifiedArtifact) validate() error {
	switch {
	case a.Version == "":
		return fmt.Errorf("agent: rollout artifact needs a version")
	case a.Digest == "":
		return fmt.Errorf("agent: rollout artifact needs the exact digest being deployed (U-006)")
	case a.Method == "":
		return fmt.Errorf("agent: rollout artifact needs the signature-verification method (C6 — how was cosign run?)")
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
}

const (
	defaultVerifyWindow = 15 * time.Minute
	defaultHeartbeatSLO = 5 * time.Minute
)

// PlanRollout partitions the live fleet into deterministic waves (the
// lifecycle cohorts: canary → early → main) for target. It fails closed on
// an unattested artifact, on a target that violates the version-skew policy
// against the control plane, and on an empty fleet. Agents already running
// the target are excluded — there is nothing to apply to them.
func PlanRollout(fleet []FleetAgent, target VerifiedArtifact, split lifecycle.Split, controlVersion string, pol lifecycle.Policy) (*RolloutPlan, error) {
	if err := target.validate(); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("agent: nothing to roll out — no live agents below %s", target.Version)
	}

	p := &RolloutPlan{Target: target, VerifyWindow: defaultVerifyWindow, HeartbeatSLO: defaultHeartbeatSLO}
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
// member must be on the target version with a heartbeat within HeartbeatSLO.
// All good → the wave completes. Stragglers inside VerifyWindow → still
// converging (no state change). Stragglers after VerifyWindow — wrong
// version, gone dark, or missing from the registry — HALT the whole rollout.
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
		case now.Sub(a.LastSeen) > p.HeartbeatSLO:
			stragglers = append(stragglers, fmt.Sprintf("%s (no heartbeat for %s — dark after upgrade?)", id, now.Sub(a.LastSeen).Round(time.Second)))
		}
	}
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
