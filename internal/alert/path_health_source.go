// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

const PathHealthMetric = "probectl_device_path_error_climb"

var ErrPathHealthSource = errors.New("alert: invalid owned path-health source")

// A test nominates the current path; it never grants access to its devices or
// sources. The current path reader resolves and authorizes each original port.
type PathHealthSourceInput struct {
	TestID          string `json:"test_id"`
	InterfaceID     string `json:"interface_id"`
	Metric          string `json:"metric"`
	LookbackSeconds int64  `json:"lookback_seconds,omitempty"`
	PollGapSeconds  int64  `json:"poll_gap_seconds,omitempty"`
}

// PathHealthRuleInput uses the normal alert delivery policy with an owned
// original-counter source, rather than an operator-supplied metric alias.
type PathHealthRuleInput struct {
	Name             string                `json:"name"`
	Enabled          *bool                 `json:"enabled,omitempty"`
	PathHealthSource PathHealthSourceInput `json:"path_health_source"`
	ForN             int                   `json:"for_n,omitempty"`
	RenotifySeconds  int                   `json:"renotify_seconds,omitempty"`
	Severity         string                `json:"severity,omitempty"`
	Channels         []ChannelSpec         `json:"channels,omitempty"`
}

func NormalizePathHealthSource(input PathHealthSourceInput) (PathHealthSourceInput, error) {
	if !canonicalQueryID(input.TestID) || !canonicalQueryID(input.InterfaceID) {
		return PathHealthSourceInput{}, ErrPathHealthSource
	}
	if input.Metric == "" {
		input.Metric = "probectl.device.if.in.errors"
	}
	if !IsPathHealthErrorMetric(input.Metric) {
		return PathHealthSourceInput{}, ErrPathHealthSource
	}
	if input.LookbackSeconds == 0 {
		input.LookbackSeconds = int64(24 * time.Hour / time.Second)
	}
	if input.PollGapSeconds == 0 {
		input.PollGapSeconds = int64(5 * time.Minute / time.Second)
	}
	for _, value := range []int64{input.LookbackSeconds, input.PollGapSeconds} {
		if value <= 0 || value > math.MaxInt64/int64(time.Second) {
			return PathHealthSourceInput{}, ErrPathHealthSource
		}
	}
	return input, nil
}

// IsPathHealthErrorMetric is the closed original-counter alert vocabulary.
func IsPathHealthErrorMetric(metric string) bool {
	switch metric {
	case "probectl.device.if.in.errors", "probectl.device.if.out.errors",
		"probectl.device.if.in.discards", "probectl.device.if.out.discards",
		"probectl.device.if.in.fcs.errors", "probectl.device.if.in.alignment.errors":
		return true
	default:
		return false
	}
}

// Configuration belongs to the existing tenant-owned alert rule. It retains a
// read-only ceiling, never a bearer or an authorization snapshot. Every source
// evaluation intersects it with the configuring user's current authority.
type PathHealthSource struct {
	PathHealthSourceInput
	Version     int              `json:"version"`
	OwnerUserID string           `json:"owner_user_id"`
	ReadGrants  []QueryReadGrant `json:"read_grants"`
}

type PathHealthSourceState struct {
	RuleID        string                 `json:"rule_id"`
	RuleUpdatedAt time.Time              `json:"rule_updated_at"`
	Configured    bool                   `json:"configured"`
	Source        *PathHealthSourceInput `json:"source,omitempty"`
}

func (s PathHealthSource) Validate() error {
	normalized, err := NormalizePathHealthSource(s.PathHealthSourceInput)
	if err != nil || normalized != s.PathHealthSourceInput || s.Version != 1 || !canonicalQueryID(s.OwnerUserID) || validateReadGrants(s.ReadGrants) != nil {
		return ErrPathHealthSource
	}
	return nil
}

func (s PathHealthSource) CredentialCeiling(tenant string) (*auth.Principal, error) {
	if s.Validate() != nil || !canonicalQueryID(tenant) {
		return nil, ErrPathHealthSource
	}
	return readGrantCeiling(tenant, s.OwnerUserID, s.ReadGrants), nil
}

// Binding is an operation's configuration identity, never access authority.
func (s PathHealthSource) Binding(tenant, rule string) (string, error) {
	if s.Validate() != nil || !canonicalQueryID(tenant) || !canonicalQueryID(rule) {
		return "", ErrPathHealthSource
	}
	raw, err := json.Marshal(struct {
		Tenant, Rule string
		Source       PathHealthSource
	}{tenant, rule, s})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}
