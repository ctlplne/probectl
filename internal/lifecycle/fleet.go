package lifecycle

import "hash/fnv"

// Cohort is a rollout ring an agent belongs to. Agents are promoted to a new
// version cohort-by-cohort: a small canary first, then early, then the main fleet.
type Cohort string

const (
	CohortCanary Cohort = "canary"
	CohortEarly  Cohort = "early"
	CohortMain   Cohort = "main"
)

// stageOrder is the order cohorts are released in.
var stageOrder = []Cohort{CohortCanary, CohortEarly, CohortMain}

// Split assigns agents to cohorts by percentage of the fleet. CanaryPercent +
// EarlyPercent of agents land in canary + early (deterministically, by a stable
// hash of the agent id); the remainder is the main cohort.
type Split struct {
	CanaryPercent int
	EarlyPercent  int
}

// DefaultSplit is a conservative 5% canary / 20% early rollout.
func DefaultSplit() Split { return Split{CanaryPercent: 5, EarlyPercent: 20} }

// normalized clamps the percentages to a sane 0..100 with canary+early <= 100.
func (s Split) normalized() Split {
	c := clamp(s.CanaryPercent, 0, 100)
	e := clamp(s.EarlyPercent, 0, 100-c)
	return Split{CanaryPercent: c, EarlyPercent: e}
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// CohortOf returns the cohort an agent belongs to. Assignment is deterministic and
// stable: the same agent id always maps to the same cohort (so an agent never
// flaps between rings across rollout steps), via a stable hash into 0..99 buckets.
func CohortOf(agentID string, split Split) Cohort {
	s := split.normalized()
	bucket := int(stableBucket(agentID))
	switch {
	case bucket < s.CanaryPercent:
		return CohortCanary
	case bucket < s.CanaryPercent+s.EarlyPercent:
		return CohortEarly
	default:
		return CohortMain
	}
}

// stableBucket hashes an agent id into 0..99.
func stableBucket(agentID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return h.Sum32() % 100
}

// Rollout is a staged fleet upgrade to TargetVersion. Stage is the pace: 0 = not
// started (every agent stays on its current version), 1 = canary released, 2 =
// canary + early, 3 = the whole fleet. An operator advances Stage one ring at a
// time, watching health between steps.
type Rollout struct {
	TargetVersion string
	Stage         int
	Split         Split
}

// Active reports whether a rollout is in progress (a target is set and at least
// one ring has been released).
func (r Rollout) Active() bool { return r.TargetVersion != "" && r.Stage > 0 }

// Released reports whether a cohort has been promoted to the target version at the
// rollout's current stage.
func (r Rollout) Released(c Cohort) bool {
	for i, sc := range stageOrder {
		if sc == c {
			return i < r.Stage
		}
	}
	return false
}

// DesiredVersion returns the version an agent should be running: the target when
// the agent's cohort has been released, otherwise its current version. With no
// active rollout, an agent simply keeps its current version.
func (r Rollout) DesiredVersion(agentID, current string) string {
	if !r.Active() {
		return current
	}
	if r.Released(CohortOf(agentID, r.Split)) {
		return r.TargetVersion
	}
	return current
}
