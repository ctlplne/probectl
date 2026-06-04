package alert

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Active-alert state surface (S-FE1). The engine is the single source of truth
// for what is firing RIGHT NOW — the UI reads this state, never invents its
// own. Silence and acknowledge are operator actions ON that state:
//
//   - Silence suppresses channel notifications (and the incident sink) for a
//     firing series until a deadline; the series stays visibly firing and the
//     silence clears automatically when it resolves or expires.
//   - Acknowledge records who has seen/owns a firing alert; it changes nothing
//     about evaluation or delivery and clears on resolve.
//
// This state lives in the engine (in-memory, per evaluator = per tenant).
// Restarting the control plane re-derives firing state on the next evaluation
// but drops silences/acks — durable silences are a noted follow-up (they would
// ride a store the way rules do).

// MaxSilence bounds a single silence request (fail closed on absurd inputs).
const MaxSilence = 7 * 24 * time.Hour

// ErrNotActive reports a silence/ack against a series that is not firing.
var ErrNotActive = errors.New("alert: series is not firing")

// ActiveAlert is the engine-truth view of one firing series.
type ActiveAlert struct {
	// Fingerprint identifies the (rule, series) pair — the handle for
	// silence/acknowledge actions. Opaque to clients.
	Fingerprint string            `json:"fingerprint"`
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	Severity    Severity          `json:"severity"`
	Metric      string            `json:"metric"`
	Labels      map[string]string `json:"labels,omitempty"`
	Value       float64           `json:"value"`
	Reason      string            `json:"reason"`
	Since       time.Time         `json:"since"`
	LastSeenAt  time.Time         `json:"last_seen_at"`

	SilencedUntil *time.Time `json:"silenced_until,omitempty"`
	AckedBy       string     `json:"acked_by,omitempty"`
	AckedAt       *time.Time `json:"acked_at,omitempty"`
}

// snapshotLocked renders one firing series (en.mu held).
func (en *Engine) snapshotLocked(key string, st *seriesState) ActiveAlert {
	a := ActiveAlert{
		Fingerprint: key,
		RuleID:      st.ruleID,
		RuleName:    st.ruleName,
		Severity:    st.severity,
		Metric:      st.metric,
		Labels:      st.labels,
		Value:       st.lastValue,
		Reason:      st.lastReason,
		Since:       st.since,
		LastSeenAt:  st.lastSeen,
	}
	if st.silencedUntil.After(en.clock()) {
		t := st.silencedUntil
		a.SilencedUntil = &t
	}
	if st.ackedBy != "" {
		t := st.ackedAt
		a.AckedBy = st.ackedBy
		a.AckedAt = &t
	}
	return a
}

// Active returns every firing series, most recent first. It is the read side
// of the alerting surface — engine truth, no derived client state.
func (en *Engine) Active() []ActiveAlert {
	en.mu.Lock()
	defer en.mu.Unlock()
	out := make([]ActiveAlert, 0, 8)
	for key, st := range en.states {
		if !st.firing {
			continue
		}
		out = append(out, en.snapshotLocked(key, st))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.After(out[j].Since)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// Silence suppresses notifications for a firing series until now+d (d == 0
// clears an existing silence). The series itself keeps evaluating and stays
// listed as firing.
func (en *Engine) Silence(fingerprint string, d time.Duration) (ActiveAlert, error) {
	if d < 0 || d > MaxSilence {
		return ActiveAlert{}, fmt.Errorf("alert: silence duration must be between 0 and %s", MaxSilence)
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	st, ok := en.states[fingerprint]
	if !ok || !st.firing {
		return ActiveAlert{}, ErrNotActive
	}
	if d == 0 {
		st.silencedUntil = time.Time{}
	} else {
		st.silencedUntil = en.clock().Add(d)
	}
	return en.snapshotLocked(fingerprint, st), nil
}

// Acknowledge records that `by` has seen/owns a firing series. Evaluation and
// delivery are unchanged; the ack clears when the series resolves.
func (en *Engine) Acknowledge(fingerprint, by string) (ActiveAlert, error) {
	if by == "" {
		by = "unknown"
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	st, ok := en.states[fingerprint]
	if !ok || !st.firing {
		return ActiveAlert{}, ErrNotActive
	}
	st.ackedBy = by
	st.ackedAt = en.clock()
	return en.snapshotLocked(fingerprint, st), nil
}
