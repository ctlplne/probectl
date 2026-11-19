// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

const SeasonalFlowMetric = "probectl_flow_seasonal_measure"

var ErrSeasonalSource = errors.New("alert: a valid current seasonal source is required")

// SeasonalBaselineInput is operator configuration. It carries no credential or
// independently trusted source claim. Without a test or saved flow view the
// rule watches its exact metric and label selector.
type SeasonalBaselineInput struct {
	Direction     SeasonalDirection       `json:"direction,omitempty"`
	Cadence       anomaly.SeasonalCadence `json:"cadence,omitempty"`
	Timezone      string                  `json:"timezone"`
	Holidays      []string                `json:"holidays,omitempty"`
	MinimumChange float64                 `json:"minimum_change"`
	TestID        string                  `json:"test_id,omitempty"`
	Flow          *SeasonalFlowInput      `json:"flow,omitempty"`
}

type SeasonalFlowInput struct {
	ViewID      string `json:"view_id"`
	ViewVersion string `json:"view_version"`
	Measure     string `json:"measure"`
}

func (s SeasonalFlowInput) Validate() error {
	name, calculation, selected := strings.Cut(s.Measure, ":")
	if !selected || name == "" || calculation == "" || strings.Contains(calculation, ":") || !canonicalQueryID(s.ViewID) {
		return ErrSeasonalSource
	}
	if _, err := flow.QueryViewVersion(s.ViewVersion); err != nil {
		return ErrSeasonalSource
	}
	return nil
}

type SeasonalSourceState struct {
	RuleID        string                 `json:"rule_id"`
	RuleUpdatedAt time.Time              `json:"rule_updated_at"`
	Configured    bool                   `json:"configured"`
	StaleRevision bool                   `json:"stale_revision,omitempty"`
	Enabled       bool                   `json:"enabled"`
	Source        *SeasonalBaselineInput `json:"source,omitempty"`
}

const SeasonalMinimumTrainingDays = 3

func (s SeasonalBaselineInput) Model() (anomaly.WeeklySeasonalModel, error) {
	if !s.Direction.valid() {
		return anomaly.WeeklySeasonalModel{}, ErrSeasonalSource
	}
	if s.Flow != nil {
		if s.TestID != "" || s.Cadence == anomaly.SeasonalHourly || s.Flow.Validate() != nil {
			return anomaly.WeeklySeasonalModel{}, ErrSeasonalSource
		}
	}
	if s.TestID != "" && !canonicalQueryID(s.TestID) {
		return anomaly.WeeklySeasonalModel{}, ErrSeasonalSource
	}
	return anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{
		Cadence: s.Cadence, Timezone: s.Timezone, Holidays: s.Holidays, MinimumDays: SeasonalMinimumTrainingDays, MinimumDeviation: s.MinimumChange,
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
