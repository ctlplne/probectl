// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
)

var ErrSeasonalSource = errors.New("alert: a valid current seasonal source is required")

// SeasonalBaselineInput is operator configuration. It carries no credential or
// independently trusted source claim. Without a test the rule watches its
// exact metric and label selector.
type SeasonalBaselineInput struct {
	Timezone      string   `json:"timezone"`
	Holidays      []string `json:"holidays,omitempty"`
	MinimumChange float64  `json:"minimum_change"`
	TestID        string   `json:"test_id,omitempty"`
}

type SeasonalSourceState struct {
	RuleID        string                 `json:"rule_id"`
	RuleUpdatedAt time.Time              `json:"rule_updated_at"`
	Configured    bool                   `json:"configured"`
	Enabled       bool                   `json:"enabled"`
	Source        *SeasonalBaselineInput `json:"source,omitempty"`
}

const SeasonalMinimumTrainingDays = 3

func (s SeasonalBaselineInput) Model() (anomaly.WeeklySeasonalModel, error) {
	if s.TestID != "" && !canonicalQueryID(s.TestID) {
		return anomaly.WeeklySeasonalModel{}, ErrSeasonalSource
	}
	return anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{
		Timezone: s.Timezone, Holidays: s.Holidays, MinimumDays: SeasonalMinimumTrainingDays, MinimumDeviation: s.MinimumChange,
	})
}

// SeasonalSource is stored with the tenant rule revision. The read grant only
// bounds the evaluator's later intersection with current authority.
type SeasonalSource struct {
	Version      int                   `json:"version"`
	OwnerUserID  string                `json:"owner_user_id"`
	Config       SeasonalBaselineInput `json:"config"`
	ReadGrants   []QueryReadGrant      `json:"read_grants"`
	TestRevision *time.Time            `json:"test_revision,omitempty"`
}

func (s SeasonalSource) CredentialCeiling(tenant string) (*auth.Principal, error) {
	if s.Version != 1 || !canonicalQueryID(tenant) || !canonicalQueryID(s.OwnerUserID) || len(s.ReadGrants) == 0 {
		return nil, ErrSeasonalSource
	}
	if (s.Config.TestID == "") != (s.TestRevision == nil) || (s.TestRevision != nil && s.TestRevision.IsZero()) {
		return nil, ErrSeasonalSource
	}
	if _, err := s.Config.Model(); err != nil {
		return nil, err
	}
	if err := validateReadGrants(s.ReadGrants); err != nil {
		return nil, err
	}
	return readGrantCeiling(tenant, s.OwnerUserID, s.ReadGrants), nil
}
