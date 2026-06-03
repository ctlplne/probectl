// Package lifecycle holds netctl's zero-downtime upgrade logic (S34, F28): the
// control-plane↔agent version-compatibility policy (the N/N-1 skew window) and the
// staged fleet-rollout model (cohorts + pace). It is pure, dependency-free logic
// so the upgrade rules are unit-testable in isolation; the agent transport and the
// control plane consume it.
package lifecycle

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Pre is the pre-release tag (without the
// leading '-'); Dev marks a non-pinned development build (e.g. "0.0.0-dev"), which
// is treated as compatible with everything so local/CI runs are never rejected.
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string
	Dev   bool
}

// Parse reads a lenient semver: an optional leading 'v', "MAJOR.MINOR.PATCH", and
// an optional "-pre" / "+build" suffix. A missing patch/minor defaults to 0. The
// development default ("0.0.0-dev"), "unknown", or an empty string parse as a Dev
// build rather than an error.
func Parse(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" || strings.EqualFold(raw, "unknown") {
		return Version{Dev: true, Pre: "dev"}, nil
	}
	v := strings.TrimPrefix(raw, "v")

	// Split off build metadata (+) then the pre-release (-).
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}

	parts := strings.SplitN(v, ".", 3)
	out := Version{Pre: pre}
	nums := []*int{&out.Major, &out.Minor, &out.Patch}
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return Version{}, fmt.Errorf("lifecycle: invalid version %q", s)
		}
		*nums[i] = n
	}
	// A 0.0.0 core or a "dev" pre-release is an unpinned development build.
	if (out.Major == 0 && out.Minor == 0 && out.Patch == 0) || strings.Contains(strings.ToLower(pre), "dev") {
		out.Dev = true
	}
	return out, nil
}

// String renders the core version (MAJOR.MINOR.PATCH[-pre]).
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare orders two versions by major, then minor, then patch (pre-release is not
// ordered — it does not affect compatibility). Returns -1, 0, or 1.
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		return sign(v.Major - o.Major)
	case v.Minor != o.Minor:
		return sign(v.Minor - o.Minor)
	case v.Patch != o.Patch:
		return sign(v.Patch - o.Patch)
	default:
		return 0
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// DefaultSkewWindow is the supported minor-version skew between the control plane
// and an agent: ±1 minor (the N/N-1 policy). A control plane at minor N accepts
// agents at N-1, N, and N+1.
const DefaultSkewWindow = 1

// Policy is the version-compatibility policy enforced at the agent handshake.
type Policy struct {
	// Window is the allowed minor-version skew on either side (default 1 = N/N-1).
	Window int
	// Min, when non-empty, is an explicit floor: an agent older than Min is rejected
	// regardless of the window (e.g. to force-retire a version with a known bug).
	Min string
}

// DefaultPolicy is the N/N-1 policy with no explicit floor.
func DefaultPolicy() Policy { return Policy{Window: DefaultSkewWindow} }

// window returns the effective window (>=0).
func (p Policy) window() int {
	if p.Window <= 0 {
		return DefaultSkewWindow
	}
	return p.Window
}

// Check reports whether an agent at agentVer may talk to a control plane at
// controlVer. It returns ok plus a human reason (the reason is informational on
// success too). The rules:
//   - either side being a dev/unpinned build → compatible (skip the check);
//   - different MAJOR version → incompatible (a breaking protocol boundary);
//   - MINOR skew greater than the window → incompatible;
//   - an agent older than an explicit Min floor → incompatible.
//
// The policy is symmetric on the window, so an N agent ↔ N+1 control plane and an
// N+1 agent ↔ N control plane are both accepted within one minor.
func (p Policy) Check(controlVer, agentVer string) (ok bool, reason string) {
	cv, err := Parse(controlVer)
	if err != nil {
		// An unparseable CONTROL version shouldn't take the fleet down; fail open.
		return true, "control version unparseable; skew check skipped"
	}
	av, err := Parse(agentVer)
	if err != nil {
		return false, fmt.Sprintf("agent version %q is unparseable", agentVer)
	}
	if cv.Dev || av.Dev {
		return true, "development build; skew check skipped"
	}
	if p.Min != "" {
		if floor, err := Parse(p.Min); err == nil && av.Compare(floor) < 0 {
			return false, fmt.Sprintf("agent %s is older than the required minimum %s", av, floor)
		}
	}
	if cv.Major != av.Major {
		return false, fmt.Sprintf("major version mismatch: control %s vs agent %s", cv, av)
	}
	skew := cv.Minor - av.Minor
	if skew < 0 {
		skew = -skew
	}
	if skew > p.window() {
		return false, fmt.Sprintf("minor-version skew %d (control %s vs agent %s) exceeds the supported window of %d", skew, cv, av, p.window())
	}
	return true, ""
}
