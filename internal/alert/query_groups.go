// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrQueryGroups = errors.New("alert: complete current saved-query groups are unavailable")

// QueryCondition compares the selected metric as an exact decimal, or watches
// the complete selected group set for new members. It contains no SQL or grant.
type QueryCondition struct {
	Mode       string     `json:"mode"`
	Metric     string     `json:"metric,omitempty"`
	Comparison Comparison `json:"comparison,omitempty"`
	Threshold  string     `json:"threshold,omitempty"`
}

// QueryGroupBinding is server-bound configuration. Current source/actor
// authorization and query-cost admission must precede evaluation; these IDs
// select a state domain and never grant access to a saved query or telemetry.
type QueryGroupBinding struct {
	TenantID, RuleID, ViewID, ViewVersion string
	Condition                             QueryCondition
}

type QueryGroup struct {
	Dimensions map[string]string
	Value      string
}

// QueryGroupSnapshot carries the full selected population before transport
// pagination. Complete must describe successful source coverage, not merely a
// successful HTTP response. A partial read cannot fire or resolve anything.
type QueryGroupSnapshot struct {
	TenantID, ViewID, ViewVersion string
	At                            time.Time
	Complete                      bool
	Groups                        []QueryGroup
}

// QueryGroupState keeps opaque, tenant/rule/revision-bound group keys only.
// The storage adapter must atomically compare its previous version and publish
// the next state with transitions after rechecking current source authority.
type QueryGroupState struct {
	Binding     string    `json:"binding"`
	Initialized bool      `json:"initialized"`
	At          time.Time `json:"at"`
	Keys        []string  `json:"keys"`
	Novel       []string  `json:"novel"`
}

// QueryGroupDecision retains the exact value for explanations. The ordinary
// alert engine consumes Breached as a Boolean condition; it must never round a
// wide counter to float64 before deciding whether the threshold was crossed.
type QueryGroupDecision struct {
	Key        string
	Dimensions map[string]string
	Value      string
	Breached   bool
	Present    bool
}

func (c QueryCondition) Validate(metrics []flow.QueryMetric) error {
	if c.Mode == "new_group" {
		if c.Metric != "" || c.Comparison != "" || c.Threshold != "" {
			return ErrQueryGroups
		}
		return nil
	}
	if c.Mode != "threshold" || !validComparisons[c.Comparison] || !queryDecimal(c.Threshold) {
		return ErrQueryGroups
	}
	for _, metric := range metrics {
		if c.Metric == metric.Measure+":"+metric.Calculation {
			return nil
		}
	}
	return ErrQueryGroups
}

func queryDecimal(text string) bool {
	if len(text) == 0 {
		return false
	}
	start := 0
	if text[0] == '-' {
		start++
	}
	digits, dot := 0, -1
	for i := start; i < len(text); i++ {
		if text[i] == '.' && dot == -1 {
			dot = i
			continue
		}
		if text[i] < '0' || text[i] > '9' {
			return false
		}
		digits++
	}
	return digits > 0 && (dot == -1 || (dot > start && dot < len(text)-1))
}

func queryBindingKey(binding QueryGroupBinding) (string, error) {
	for _, id := range []string{binding.TenantID, binding.RuleID, binding.ViewID} {
		value, err := gouuid.Parse(id)
		if err != nil || value == gouuid.Nil || value.String() != id {
			return "", ErrQueryGroups
		}
	}
	if _, err := flow.QueryViewVersion(binding.ViewVersion); err != nil {
		return "", ErrQueryGroups
	}
	// JSON framing preserves embedded separators and Unicode in group values.
	body, err := json.Marshal(struct {
		Domain  string
		Binding QueryGroupBinding
	}{"probectl.saved-query-alert.v1", binding})
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(body)
	if len(digest) != 32 {
		return "", ErrQueryGroups
	}
	return hex.EncodeToString(digest), nil
}

// QueryGroupBudget is the source operation's remaining resource allowance,
// separate from any row count or top-N selection in the saved query.
type QueryGroupBudget struct{ MemoryBytes, WorkUnits int64 }

func (b *QueryGroupBudget) charge(bytes int64) error {
	if bytes < 0 || bytes > b.MemoryBytes || bytes > b.WorkUnits {
		return ErrQueryGroups
	}
	b.MemoryBytes -= bytes
	b.WorkUnits -= bytes
	return nil
}

// Rat parsing/comparison work is quadratic in admitted decimal digits. Charge
// that work before big-number allocation, without imposing a value-size cap.
func (b *QueryGroupBudget) decimalWork(size int64) error {
	if size <= 0 || size > b.WorkUnits/size {
		return ErrQueryGroups
	}
	b.WorkUnits -= size * size
	return nil
}

func queryPreviousKeys(ctx context.Context, binding string, previous QueryGroupState, at time.Time, budget *QueryGroupBudget) (map[string]bool, map[string]bool, error) {
	keys, novel := map[string]bool{}, map[string]bool{}
	if !previous.Initialized {
		if previous.Binding != "" || !previous.At.IsZero() || len(previous.Keys) != 0 || len(previous.Novel) != 0 {
			return nil, nil, ErrQueryGroups
		}
		return keys, novel, nil
	}
	if previous.Binding != binding || previous.At.IsZero() || !at.After(previous.At) {
		return nil, nil, ErrQueryGroups
	}
	for _, key := range previous.Keys {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != key || keys[key] || budget.charge(256) != nil {
			return nil, nil, ErrQueryGroups
		}
		keys[key] = true
	}
	for _, key := range previous.Novel {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !keys[key] || novel[key] || budget.charge(128) != nil {
			return nil, nil, ErrQueryGroups
		}
		novel[key] = true
	}
	return keys, novel, nil
}

func queryGroupKey(binding string, group QueryGroup, budget *QueryGroupBudget) (string, map[string]string, error) {
	if err := budget.charge(1024 + int64(len(group.Value))*8 + int64(len(group.Dimensions))*256); err != nil {
		return "", nil, err
	}
	owned := make(map[string]string, len(group.Dimensions))
	for key, value := range group.Dimensions {
		if key == "" || budget.charge(int64(len(key))*8+int64(len(value))*8) != nil {
			return "", nil, ErrQueryGroups
		}
		owned[key] = value
	}
	body, err := json.Marshal(struct {
		Binding string
		Group   map[string]string
	}{binding, owned})
	if err != nil {
		return "", nil, err
	}
	digest := crypto.Hash(body)
	if len(digest) != 32 {
		return "", nil, ErrQueryGroups
	}
	return hex.EncodeToString(digest), owned, nil
}

func queryGroupBreached(condition QueryCondition, value string, threshold *big.Rat) (bool, error) {
	if !queryDecimal(value) {
		return false, ErrQueryGroups
	}
	actual, ok := new(big.Rat).SetString(value)
	if !ok {
		return false, ErrQueryGroups
	}
	comparison := actual.Cmp(threshold)
	switch condition.Comparison {
	case GT:
		return comparison > 0, nil
	case GTE:
		return comparison >= 0, nil
	case LT:
		return comparison < 0, nil
	case LTE:
		return comparison <= 0, nil
	case EQ:
		return comparison == 0, nil
	case NEQ:
		return comparison != 0, nil
	default:
		return false, ErrQueryGroups
	}
}

// EvaluateQueryGroups has no effects. On any refusal it returns neither next
// state nor partial transitions. Missing groups resolve only after a complete
// admitted snapshot; the first new-group snapshot warms without firing.
func EvaluateQueryGroups(ctx context.Context, binding QueryGroupBinding, snapshot QueryGroupSnapshot, previous QueryGroupState, budget QueryGroupBudget) ([]QueryGroupDecision, QueryGroupState, error) {
	if err := ctx.Err(); err != nil {
		return nil, QueryGroupState{}, err
	}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant.String() != binding.TenantID {
		return nil, QueryGroupState{}, tenancy.ErrNoTenant
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || !snapshot.Complete || snapshot.At.IsZero() || snapshot.TenantID != binding.TenantID || snapshot.ViewID != binding.ViewID || snapshot.ViewVersion != binding.ViewVersion {
		return nil, QueryGroupState{}, ErrQueryGroups
	}
	if err := budget.charge(4096 + int64(len(binding.Condition.Threshold))*8); err != nil {
		return nil, QueryGroupState{}, err
	}
	key, err := queryBindingKey(binding)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	old, novel, err := queryPreviousKeys(ctx, key, previous, snapshot.At, &budget)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	if binding.Condition.Mode == "threshold" {
		if err := budget.decimalWork(int64(len(binding.Condition.Threshold))); err != nil {
			return nil, QueryGroupState{}, err
		}
	}
	threshold, err := queryGroupThreshold(binding.Condition)
	if err != nil {
		return nil, QueryGroupState{}, err
	}
	return evaluateCurrentQueryGroups(ctx, binding.Condition, snapshot, previous.Initialized, key, old, novel, threshold, &budget)
}

func queryGroupThreshold(condition QueryCondition) (*big.Rat, error) {
	if condition.Mode == "new_group" && condition.Metric == "" && condition.Comparison == "" && condition.Threshold == "" {
		return nil, nil
	}
	if condition.Mode != "threshold" || condition.Metric == "" || !validComparisons[condition.Comparison] || !queryDecimal(condition.Threshold) {
		return nil, ErrQueryGroups
	}
	value, ok := new(big.Rat).SetString(condition.Threshold)
	if !ok {
		return nil, ErrQueryGroups
	}
	return value, nil
}

func evaluateCurrentQueryGroups(ctx context.Context, condition QueryCondition, snapshot QueryGroupSnapshot, initialized bool, binding string, previous, novel map[string]bool, threshold *big.Rat, budget *QueryGroupBudget) ([]QueryGroupDecision, QueryGroupState, error) {
	next := QueryGroupState{Binding: binding, Initialized: true, At: snapshot.At.UTC(), Keys: []string{}, Novel: []string{}}
	current := map[string]bool{}
	decisions := []QueryGroupDecision{}
	for _, group := range snapshot.Groups {
		if err := ctx.Err(); err != nil {
			return nil, QueryGroupState{}, err
		}
		key, dimensions, err := queryGroupKey(binding, group, budget)
		if err != nil || current[key] {
			return nil, QueryGroupState{}, ErrQueryGroups
		}
		breached := initialized && (!previous[key] || novel[key])
		if condition.Mode == "threshold" {
			if err := budget.decimalWork(int64(len(group.Value)) + int64(len(condition.Threshold))); err != nil {
				return nil, QueryGroupState{}, err
			}
			breached, err = queryGroupBreached(condition, group.Value, threshold)
			if err != nil {
				return nil, QueryGroupState{}, err
			}
		} else if breached {
			next.Novel = append(next.Novel, key)
		}
		current[key] = true
		next.Keys = append(next.Keys, key)
		decisions = append(decisions, QueryGroupDecision{Key: key, Dimensions: dimensions, Value: group.Value, Breached: breached, Present: true})
	}
	for key := range previous {
		if !current[key] {
			if err := ctx.Err(); err != nil {
				return nil, QueryGroupState{}, err
			}
			decisions = append(decisions, QueryGroupDecision{Key: key})
		}
	}
	sort.Strings(next.Keys)
	sort.Strings(next.Novel)
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].Key < decisions[j].Key })
	return decisions, next, nil
}
