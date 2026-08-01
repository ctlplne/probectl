// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

const (
	CollectionStateOKWithRows    = "ok_with_rows"
	CollectionStateHealthyEmpty  = "healthy_empty"
	CollectionStateUnsupported   = "unsupported"
	CollectionStateFailed        = "failed"
	CollectionStateNeverObserved = "never_observed"

	CollectionReasonRowsObserved          = "rows_observed"
	CollectionReasonNoRowsObserved        = "no_rows_observed"
	CollectionReasonMIBUnsupported        = "mib_unsupported"
	CollectionReasonPollFailed            = "poll_failed"
	CollectionReasonCredentialUnavailable = "credential_unavailable"
	CollectionReasonTransportUnreachable  = "transport_unreachable"
	CollectionReasonBasePollFailed        = "base_poll_failed"
	CollectionReasonNeverAttempted        = "never_attempted"

	CollectionActionReviewEvidence      = "review_neighbor_evidence"
	CollectionActionReviewConfiguration = "review_target_neighbor_configuration"
	CollectionActionEnableProtocol      = "enable_protocol_on_configured_target"
	CollectionActionVerifyLocalAccess   = "verify_configured_target_access"
	CollectionActionWaitForFirstAttempt = "wait_for_first_collection"

	MaxCollectionOutcomesPerTenant = 4_096
	MaxCollectionOutcomeRead       = 500
	CollectionOutcomeRetention     = 30 * 24 * time.Hour
)

// CollectionOutcome is one bounded readiness receipt for one explicitly
// configured target and one read-only discovery protocol. It deliberately
// excludes credentials, raw varbinds, and discovered neighbor identities.
type CollectionOutcome struct {
	TenantID         string     `json:"-"`
	AgentID          string     `json:"agent_id"`
	ConfiguredTarget string     `json:"configured_target"`
	Protocol         string     `json:"protocol"`
	LastAttemptAt    *time.Time `json:"last_attempt_at"`
	LastSuccessAt    *time.Time `json:"last_success_at"`
	State            string     `json:"state"`
	Reason           string     `json:"reason"`
	RowCount         int        `json:"row_count"`
	NextAction       string     `json:"next_action"`
}

// CollectionOutcomeFilter bounds tenant-scoped readiness reads.
type CollectionOutcomeFilter struct {
	AgentID string
	Target  string
	State   string
	Limit   int
}

// CollectionOutcomeStore is the tenant-first current-receipt persistence seam.
type CollectionOutcomeStore interface {
	UpsertCollectionOutcome(context.Context, string, CollectionOutcome) error
	ListCollectionOutcomes(context.Context, string, CollectionOutcomeFilter) ([]CollectionOutcome, bool, error)
}

var (
	collectionStates = map[string]struct{}{
		CollectionStateOKWithRows: {}, CollectionStateHealthyEmpty: {},
		CollectionStateUnsupported: {}, CollectionStateFailed: {},
		CollectionStateNeverObserved: {},
	}
	collectionReasons = map[string]struct{}{
		CollectionReasonRowsObserved: {}, CollectionReasonNoRowsObserved: {},
		CollectionReasonMIBUnsupported: {}, CollectionReasonPollFailed: {},
		CollectionReasonCredentialUnavailable: {}, CollectionReasonTransportUnreachable: {},
		CollectionReasonBasePollFailed: {}, CollectionReasonNeverAttempted: {},
	}
	collectionActions = map[string]struct{}{
		CollectionActionReviewEvidence: {}, CollectionActionReviewConfiguration: {},
		CollectionActionEnableProtocol: {}, CollectionActionVerifyLocalAccess: {},
		CollectionActionWaitForFirstAttempt: {},
	}
)

// ValidateCollectionOutcome applies the same strict allowlist and bounds at
// producer, consumer, and storage edges. Free-form errors never enter a receipt.
func ValidateCollectionOutcome(in CollectionOutcome) (CollectionOutcome, error) {
	in.TenantID = boundedText(in.TenantID, 128)
	in.AgentID = boundedText(in.AgentID, 128)
	in.ConfiguredTarget = boundedText(in.ConfiguredTarget, 255)
	in.Protocol = strings.ToLower(boundedText(in.Protocol, 8))
	in.State = strings.ToLower(boundedText(in.State, 32))
	in.Reason = strings.ToLower(boundedText(in.Reason, 48))
	in.NextAction = strings.ToLower(boundedText(in.NextAction, 64))
	if in.TenantID == "" || in.AgentID == "" || in.ConfiguredTarget == "" {
		return CollectionOutcome{}, errors.New("device collection outcome: tenant_id, agent_id, and configured_target are required")
	}
	if in.Protocol != NeighborProtocolLLDP && in.Protocol != NeighborProtocolCDP {
		return CollectionOutcome{}, errors.New("device collection outcome: protocol must be lldp or cdp")
	}
	if _, ok := collectionStates[in.State]; !ok {
		return CollectionOutcome{}, errors.New("device collection outcome: invalid state")
	}
	if _, ok := collectionReasons[in.Reason]; !ok {
		return CollectionOutcome{}, errors.New("device collection outcome: invalid reason")
	}
	if _, ok := collectionActions[in.NextAction]; !ok {
		return CollectionOutcome{}, errors.New("device collection outcome: invalid next_action")
	}
	if in.RowCount < 0 || in.RowCount > MaxNeighborsPerDevice {
		return CollectionOutcome{}, errors.New("device collection outcome: row_count is out of bounds")
	}
	if in.State == CollectionStateNeverObserved {
		if in.LastAttemptAt != nil || in.LastSuccessAt != nil || in.RowCount != 0 {
			return CollectionOutcome{}, errors.New("device collection outcome: never_observed cannot contain attempt evidence")
		}
	} else if in.LastAttemptAt == nil || in.LastAttemptAt.IsZero() {
		return CollectionOutcome{}, errors.New("device collection outcome: last_attempt_at is required")
	}
	if in.LastAttemptAt != nil {
		at := in.LastAttemptAt.UTC()
		in.LastAttemptAt = &at
	}
	if in.LastSuccessAt != nil {
		success := in.LastSuccessAt.UTC()
		if success.IsZero() || in.LastAttemptAt == nil || success.After(*in.LastAttemptAt) {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid last_success_at")
		}
		in.LastSuccessAt = &success
	}
	if in.State == CollectionStateOKWithRows && in.RowCount == 0 {
		return CollectionOutcome{}, errors.New("device collection outcome: ok_with_rows requires rows")
	}
	if in.State != CollectionStateOKWithRows && in.RowCount != 0 {
		return CollectionOutcome{}, errors.New("device collection outcome: only ok_with_rows may contain rows")
	}
	switch in.State {
	case CollectionStateOKWithRows:
		if in.Reason != CollectionReasonRowsObserved || in.NextAction != CollectionActionReviewEvidence ||
			in.LastSuccessAt == nil {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid ok_with_rows receipt")
		}
	case CollectionStateHealthyEmpty:
		if in.Reason != CollectionReasonNoRowsObserved ||
			in.NextAction != CollectionActionReviewConfiguration || in.LastSuccessAt == nil {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid healthy_empty receipt")
		}
	case CollectionStateUnsupported:
		if in.Reason != CollectionReasonMIBUnsupported || in.NextAction != CollectionActionEnableProtocol {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid unsupported receipt")
		}
	case CollectionStateFailed:
		if (in.Reason != CollectionReasonPollFailed &&
			in.Reason != CollectionReasonCredentialUnavailable &&
			in.Reason != CollectionReasonTransportUnreachable &&
			in.Reason != CollectionReasonBasePollFailed) ||
			in.NextAction != CollectionActionVerifyLocalAccess {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid failed receipt")
		}
	case CollectionStateNeverObserved:
		if in.Reason != CollectionReasonNeverAttempted || in.NextAction != CollectionActionWaitForFirstAttempt {
			return CollectionOutcome{}, errors.New("device collection outcome: invalid never_observed receipt")
		}
	}
	return in, nil
}

// ValidCollectionState reports whether state is one of the stable wire values.
func ValidCollectionState(state string) bool {
	_, ok := collectionStates[strings.ToLower(strings.TrimSpace(state))]
	return ok
}

func (o CollectionOutcome) ToProto() *devicev1.DeviceCollectionOutcome {
	out := &devicev1.DeviceCollectionOutcome{
		TenantId: o.TenantID, AgentId: o.AgentID, ConfiguredTarget: o.ConfiguredTarget,
		Protocol: o.Protocol, State: o.State, Reason: o.Reason,
		RowCount: uint32(o.RowCount), NextAction: o.NextAction,
	}
	if o.LastAttemptAt != nil {
		out.LastAttemptAtUnixNano = o.LastAttemptAt.UnixNano()
	}
	if o.LastSuccessAt != nil {
		out.LastSuccessAtUnixNano = o.LastSuccessAt.UnixNano()
	}
	return out
}

func CollectionOutcomeFromProto(in *devicev1.DeviceCollectionOutcome) CollectionOutcome {
	if in == nil {
		return CollectionOutcome{}
	}
	out := CollectionOutcome{
		TenantID: in.GetTenantId(), AgentID: in.GetAgentId(),
		ConfiguredTarget: in.GetConfiguredTarget(), Protocol: in.GetProtocol(),
		State: in.GetState(), Reason: in.GetReason(), RowCount: int(in.GetRowCount()),
		NextAction: in.GetNextAction(),
	}
	if in.GetLastAttemptAtUnixNano() != 0 {
		at := time.Unix(0, in.GetLastAttemptAtUnixNano()).UTC()
		out.LastAttemptAt = &at
	}
	if in.GetLastSuccessAtUnixNano() != 0 {
		at := time.Unix(0, in.GetLastSuccessAtUnixNano()).UTC()
		out.LastSuccessAt = &at
	}
	return out
}

// MemoryCollectionOutcomeStore is a bounded tenant-keyed implementation for
// tests and lightweight control-plane profiles.
type MemoryCollectionOutcomeStore struct {
	mu   sync.RWMutex
	rows map[string]map[string]CollectionOutcome
}

func NewMemoryCollectionOutcomeStore() *MemoryCollectionOutcomeStore {
	return &MemoryCollectionOutcomeStore{rows: map[string]map[string]CollectionOutcome{}}
}

func (m *MemoryCollectionOutcomeStore) UpsertCollectionOutcome(_ context.Context, tenant string, outcome CollectionOutcome) error {
	if tenant == "" || outcome.TenantID != tenant {
		return errors.New("device collection outcomes: tenant scope mismatch")
	}
	valid, err := ValidateCollectionOutcome(outcome)
	if err != nil {
		return err
	}
	key := valid.AgentID + "\x00" + valid.ConfiguredTarget + "\x00" + valid.Protocol
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]CollectionOutcome{}
	}
	current, exists := m.rows[tenant][key]
	if exists && current.LastAttemptAt != nil &&
		(valid.LastAttemptAt == nil || valid.LastAttemptAt.Before(*current.LastAttemptAt)) {
		return nil
	}
	if current.LastSuccessAt != nil &&
		(valid.LastSuccessAt == nil || current.LastSuccessAt.After(*valid.LastSuccessAt)) {
		success := current.LastSuccessAt.UTC()
		valid.LastSuccessAt = &success
	}
	m.rows[tenant][key] = valid

	type keyedOutcome struct {
		key string
		row CollectionOutcome
	}
	all := make([]keyedOutcome, 0, len(m.rows[tenant]))
	for rowKey, row := range m.rows[tenant] {
		all = append(all, keyedOutcome{key: rowKey, row: row})
	}
	sort.Slice(all, func(i, j int) bool {
		left, right := all[i].row.LastAttemptAt, all[j].row.LastAttemptAt
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		if !left.Equal(*right) {
			return left.After(*right)
		}
		return all[i].key < all[j].key
	})
	if len(all) > MaxCollectionOutcomesPerTenant {
		for _, stale := range all[MaxCollectionOutcomesPerTenant:] {
			delete(m.rows[tenant], stale.key)
		}
	}
	return nil
}

func (m *MemoryCollectionOutcomeStore) ListCollectionOutcomes(_ context.Context, tenant string, filter CollectionOutcomeFilter) ([]CollectionOutcome, bool, error) {
	if tenant == "" {
		return nil, false, errors.New("device collection outcomes: tenant_id is required")
	}
	filter.AgentID = strings.TrimSpace(filter.AgentID)
	filter.Target = strings.TrimSpace(filter.Target)
	filter.State = strings.ToLower(strings.TrimSpace(filter.State))
	if filter.State != "" && !ValidCollectionState(filter.State) {
		return nil, false, errors.New("device collection outcomes: invalid state")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > MaxCollectionOutcomeRead {
		limit = MaxCollectionOutcomeRead
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]CollectionOutcome, 0, len(m.rows[tenant]))
	for _, row := range m.rows[tenant] {
		if filter.AgentID != "" && row.AgentID != filter.AgentID {
			continue
		}
		if filter.Target != "" && row.ConfiguredTarget != filter.Target {
			continue
		}
		if filter.State != "" && row.State != filter.State {
			continue
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i].LastAttemptAt, out[j].LastAttemptAt
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		if !left.Equal(*right) {
			return left.After(*right)
		}
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		if out[i].ConfiguredTarget != out[j].ConfiguredTarget {
			return out[i].ConfiguredTarget < out[j].ConfiguredTarget
		}
		return out[i].Protocol < out[j].Protocol
	})
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

var _ CollectionOutcomeStore = (*MemoryCollectionOutcomeStore)(nil)
