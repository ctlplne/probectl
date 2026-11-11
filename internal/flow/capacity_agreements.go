// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrCapacityAgreementInvalid  = errors.New("complete capacity agreement is required")
	ErrCapacityAgreementNotFound = errors.New("capacity agreement not found")
	ErrCapacityAgreementConflict = errors.New("capacity agreement revision conflict")
	ErrCapacityAgreementBudget   = errors.New("complete capacity agreement exceeds resource admission")
)

// CapacityTarget selects canonical tenant-owned inventory, never an exporter
// address as an ownership hint. A circuit is the selected immutable tag
// definition and its complete value, resolved against current interface facts.
type CapacityTarget struct {
	Kind        string `json:"kind"`
	ContextID   string `json:"context_id,omitempty"`
	InterfaceID string `json:"interface_id,omitempty"`
	TagID       string `json:"tag_id,omitempty"`
	TagValue    string `json:"tag_value,omitempty"`
}

// CapacityAgreementDefinition records operator terms. It neither grants
// telemetry access nor infers pricing or a physical line-rate upper bound.
type CapacityAgreementDefinition struct {
	Name       string         `json:"name"`
	Reference  string         `json:"reference"`
	ValidFrom  string         `json:"valid_from"`
	Target     CapacityTarget `json:"target"`
	BillingDay int            `json:"billing_day"`
	Timezone   string         `json:"timezone"`
	Direction  string         `json:"direction"`
	Currency   string         `json:"currency"`
	CommitBPS  string         `json:"commit_bps"`
	UnitBPS    string         `json:"unit_bps"`
	UnitPrice  string         `json:"unit_price"`
}

type CapacityAgreement struct {
	ID             string                      `json:"id"`
	TenantID       string                      `json:"-"`
	CurrentVersion string                      `json:"current_version"`
	Version        string                      `json:"version"`
	Definition     CapacityAgreementDefinition `json:"definition"`
	TargetPresent  bool                        `json:"target_present"`
	CreatedAt      time.Time                   `json:"created_at"`
	UpdatedAt      time.Time                   `json:"updated_at"`
	RecordedAt     time.Time                   `json:"recorded_at"`
}

type SaveCapacityAgreement struct {
	ID         string                      `json:"id,omitempty"`
	Version    string                      `json:"version,omitempty"`
	Definition CapacityAgreementDefinition `json:"definition"`
}

type CapacityAgreementList struct {
	After string
	Limit int
}

type CapacityAgreementPage struct {
	Items   []CapacityAgreement `json:"items"`
	Next    string              `json:"next,omitempty"`
	HasMore bool                `json:"has_more"`
	AsOf    time.Time           `json:"as_of"`
}

func capacityAgreementUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func capacityAgreementText(value string, required bool) bool {
	return (!required || value != "") && strings.TrimSpace(value) == value && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// NormalizeCapacityAgreement validates a complete operator configuration under
// one tenant and finite resources. Storage must bind target references with
// tenant-scoped FKs; this routine confers no source or actor grant.
func NormalizeCapacityAgreement(ctx context.Context, input CapacityAgreementDefinition, memoryBytes, workUnits int64) (CapacityAgreementDefinition, error) {
	none := CapacityAgreementDefinition{}
	if _, ok := tenancy.FromContext(ctx); !ok {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if memoryBytes < 1<<20 || workUnits < 4096 {
		return none, ErrCapacityAgreementBudget
	}
	remaining := memoryBytes - (1 << 20)
	for _, value := range []string{input.Name, input.Reference, input.ValidFrom, input.Target.Kind, input.Target.ContextID, input.Target.InterfaceID, input.Target.TagID, input.Target.TagValue, input.Timezone, input.Direction, input.Currency, input.CommitBPS, input.UnitBPS, input.UnitPrice} {
		size := int64(len(value))
		if size > remaining/64 || size > workUnits/64 {
			return none, ErrCapacityAgreementBudget
		}
		remaining, workUnits = remaining-size*64, workUnits-size*64
	}
	if !capacityAgreementText(input.Name, true) || !capacityAgreementText(input.Reference, false) || !capacityAgreementText(input.Currency, true) || !capacityAgreementText(input.Timezone, true) || input.Timezone == "Local" || input.BillingDay < 1 || input.BillingDay > 31 {
		return none, ErrCapacityAgreementInvalid
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return none, ErrCapacityAgreementInvalid
	}
	validFrom, err := time.Parse(time.RFC3339Nano, input.ValidFrom)
	if err != nil {
		return none, ErrCapacityAgreementInvalid
	}
	input.ValidFrom = validFrom.UTC().Format(time.RFC3339Nano)
	switch capacityBillingMode(input.Direction) {
	case capacityBillingIn, capacityBillingOut, capacityBillingMaxPercentiles, capacityBillingIntervalMax, capacityBillingIntervalSum:
	default:
		return none, ErrCapacityAgreementInvalid
	}
	switch input.Target.Kind {
	case "interface":
		if !capacityAgreementUUID(input.Target.ContextID) || !capacityAgreementUUID(input.Target.InterfaceID) || input.Target.TagID != "" || input.Target.TagValue != "" {
			return none, ErrCapacityAgreementInvalid
		}
	case "circuit":
		if !capacityAgreementUUID(input.Target.TagID) || !capacityAgreementText(input.Target.TagValue, true) || input.Target.ContextID != "" || input.Target.InterfaceID != "" {
			return none, ErrCapacityAgreementInvalid
		}
	default:
		return none, ErrCapacityAgreementInvalid
	}
	words := int64(1)
	for _, text := range []string{input.CommitBPS, input.UnitBPS, input.UnitPrice} {
		words += int64(len(text))/8 + 1
	}
	if words > workUnits/512 || words > (workUnits/512)/words {
		return none, ErrCapacityAgreementBudget
	}
	if _, err := capacityContractDecimal(ctx, input.CommitBPS); err != nil {
		return none, ErrCapacityAgreementInvalid
	}
	unit, err := capacityContractDecimal(ctx, input.UnitBPS)
	if err != nil || unit.Sign() == 0 {
		return none, ErrCapacityAgreementInvalid
	}
	if _, err := capacityMonetaryDecimal(ctx, input.UnitPrice); err != nil {
		return none, ErrCapacityAgreementInvalid
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return input, nil
}
