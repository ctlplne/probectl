// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrCounterHistoryInput       = errors.New("complete scoped counter history is required")
	ErrCounterHistoryBudget      = errors.New("complete counter history exceeds resource admission")
	ErrCounterHistoryUnavailable = errors.New("counter history is unavailable")
)

// CounterSource is selected by the current operator binding under tenant RLS,
// never by an IP address or the counter payload. Assignment clocks distinguish
// an old binding from a new one even when all UUIDs and source strings repeat.
type CounterSource struct {
	ContextID, DeviceID, AgentID, SourceRef string
	SourceAssignedAt, AgentAssignedAt       time.Time
}

// CounterRow contains exact observations and private write provenance. It
// confers no actor/source read grant and carries no legacy rounded value.
type CounterRow struct {
	InterfaceSpeedBPS   uint64
	InterfaceSpeedKnown bool
	TenantID            string
	CounterSource
	SenderSerial                               string
	CaptureKey, RawDigest                      [32]byte
	CapturedAt, PollStartedAt, PollCompletedAt time.Time
	Population                                 uint32
	IfIndex                                    uint32
	Name                                       string
	Value                                      uint64
	Width                                      uint32
	UptimeTicks, DiscontinuityTicks            uint32
	UptimeKnown, DiscontinuityKnown            bool
}

// CounterBudget admits the whole operation, never a shortened row population.
// The caller supplies the operator's resources and a finite execution budget.
type CounterBudget struct {
	MemoryBytes, WorkUnits int64
	Timeout                time.Duration
}

type CounterSelector struct {
	CounterSource
	IfIndexes []uint32
}

// CounterQuery always names the complete authorized current source/interface
// set. Empty selectors never mean an implicit tenant-wide telemetry read.
type CounterQuery struct {
	TenantID string
	From, To time.Time
	Sources  []CounterSelector
	Budget   CounterBudget
}

// CounterHistory is a separate lifecycle plane from flow export. Concrete
// stores share the existing routed ClickHouse/reader infrastructure, while
// export, retention and erasure account for the counter rows independently.
type CounterHistory interface {
	InsertCounterPoll(context.Context, []CounterRow, CounterBudget) error
	CounterPoints(context.Context, CounterQuery) ([]CounterRow, error)
	// WalkCounterPoints streams one scoped, ordered series at a time. A caller
	// must discard its calculation if the walk returns any error, including a
	// backend failure after earlier rows. A prefix is never a complete result.
	WalkCounterPoints(context.Context, CounterQuery, func(CounterRow) error) error
	DeleteCounterTenant(context.Context, string) (int64, error)
	DeleteCounterSubject(context.Context, string, string) (int64, int64, error)
	DeleteCounterSubjects(context.Context, string, []string) (int64, int64, error)
	DeleteCountersBefore(context.Context, string, time.Time) error
	ExportCounterTenant(context.Context, string, io.Writer) (int64, error)
	ExportCounterSubject(context.Context, string, string, io.Writer) (int64, error)
	ExportCounterSubjects(context.Context, string, []string, io.Writer) (int64, error)
}

// CounterHistoryOf preserves this independent telemetry/lifecycle capability
// through the existing flow decorators. It confers no source or actor grant;
// runtime writes must still enter through the authenticated publication guard.
func CounterHistoryOf(store Store) (CounterHistory, bool) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			result, ok := store.(CounterHistory)
			return result, ok
		}
	}
}

func counterCanonicalUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func counterClock(at time.Time) bool {
	ns := at.UnixNano()
	return ns > 0 && time.Unix(0, ns).Equal(at)
}

func validateCounterSource(source CounterSource) error {
	key := entity.SourceKey{AgentID: source.AgentID, Kind: entity.DeviceTarget, SourceRef: source.SourceRef}
	normalized, err := key.Normalize()
	if err != nil || normalized != key || !utf8.ValidString(source.AgentID) || !utf8.ValidString(source.SourceRef) ||
		!counterCanonicalUUID(source.ContextID) || !counterCanonicalUUID(source.DeviceID) ||
		!counterClock(source.SourceAssignedAt) || !counterClock(source.AgentAssignedAt) {
		return ErrCounterHistoryInput
	}
	return nil
}

func validateCounterTenant(ctx context.Context, tenant string) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !counterCanonicalUUID(tenant) {
		return ErrCounterHistoryInput
	}
	return ctx.Err()
}

func counterRowCharge(row CounterRow) int64 {
	charge := int64(1024)
	for _, value := range []string{row.TenantID, row.ContextID, row.DeviceID, row.AgentID, row.SourceRef, row.SenderSerial, row.Name} {
		size := int64(len(value))
		if size > (math.MaxInt64-charge)/16 {
			return 0
		}
		charge += size * 16
	}
	return charge
}

func sameCounterSource(a, b CounterSource) bool {
	return a.ContextID == b.ContextID && a.DeviceID == b.DeviceID && a.AgentID == b.AgentID && a.SourceRef == b.SourceRef &&
		a.SourceAssignedAt.Equal(b.SourceAssignedAt) && a.AgentAssignedAt.Equal(b.AgentAssignedAt)
}

func validateCounterObservation(row CounterRow) error {
	if !counterCanonicalUUID(row.TenantID) {
		return ErrCounterHistoryInput
	}
	if err := validateCounterSource(row.CounterSource); err != nil {
		return err
	}
	if !counterClock(row.CapturedAt) || !counterClock(row.PollStartedAt) || !counterClock(row.PollCompletedAt) || row.PollCompletedAt.Before(row.PollStartedAt) ||
		row.PollStartedAt.Before(row.SourceAssignedAt) || row.PollStartedAt.Before(row.AgentAssignedAt) ||
		row.SenderSerial == "" || len(row.SenderSerial) > 256 || strings.TrimSpace(row.SenderSerial) != row.SenderSerial || !utf8.ValidString(row.SenderSerial) || strings.IndexFunc(row.SenderSerial, unicode.IsControl) >= 0 ||
		row.IfIndex == 0 || !counterHistoryMetricName(row.Name) ||
		(row.Width != 32 && row.Width != 64) || (row.Width == 32 && row.Value > 1<<32-1) ||
		(!row.InterfaceSpeedKnown && row.InterfaceSpeedBPS != 0) || (!row.UptimeKnown && row.UptimeTicks != 0) || (!row.DiscontinuityKnown && row.DiscontinuityTicks != 0) {
		return ErrCounterHistoryInput
	}
	expected, err := entity.CounterCaptureKey(row.TenantID, row.AgentID, row.RawDigest,
		entity.CounterCaptureInput{ConfiguredTarget: row.SourceRef, PollStartedAt: row.PollStartedAt, PollCompletedAt: row.PollCompletedAt, PointCount: row.Population})
	if err != nil || expected != row.CaptureKey {
		return ErrCounterHistoryInput
	}
	return nil
}

// This is the same six wire names admitted by the native raw-counter lane;
// arbitrary free-form metric names are not authenticated counter observations.
func counterHistoryMetricName(name string) bool {
	switch name {
	case "probectl.device.if.in.octets", "probectl.device.if.out.octets",
		"probectl.device.if.in.errors", "probectl.device.if.out.errors",
		"probectl.device.if.in.discards", "probectl.device.if.out.discards":
		return true
	}
	return false
}

// Validate before any backend writes a row. One original poll is atomic at
// admission: mixed tenants, source incarnations or duplicate points cannot
// publish a prefix. The authenticated raw consumer separately verifies that
// these rows came from the complete digest's original bytes.
func validateCounterPoll(ctx context.Context, rows []CounterRow, budget CounterBudget) error {
	if len(rows) == 0 || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.Timeout <= 0 {
		return ErrCounterHistoryInput
	}
	first := rows[0]
	if err := validateCounterTenant(ctx, first.TenantID); err != nil {
		return err
	}
	if err := validateCounterObservation(first); err != nil {
		return err
	}
	if uint64(len(rows)) > 1<<32-1 || first.Population != uint32(len(rows)) {
		return ErrCounterHistoryInput
	}
	type point struct {
		index uint32
		name  string
	}
	// Reserve duplicate-index workspace before allocating it.
	if int64(len(rows)) > budget.MemoryBytes/1024 || int64(len(rows)) > budget.WorkUnits/1024 {
		return ErrCounterHistoryBudget
	}
	seen := make(map[point]struct{}, len(rows))
	type speedWord struct {
		known bool
		value uint64
	}
	speeds := make(map[uint32]speedWord)
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		charge := counterRowCharge(row)
		if charge <= 0 || charge > budget.MemoryBytes || charge > budget.WorkUnits {
			return ErrCounterHistoryBudget
		}
		budget.MemoryBytes, budget.WorkUnits = budget.MemoryBytes-charge, budget.WorkUnits-charge
		if row.TenantID != first.TenantID || !sameCounterSource(row.CounterSource, first.CounterSource) || row.SenderSerial != first.SenderSerial ||
			row.CaptureKey != first.CaptureKey || row.RawDigest != first.RawDigest || row.Population != first.Population ||
			!row.CapturedAt.Equal(first.CapturedAt) || !row.PollStartedAt.Equal(first.PollStartedAt) || !row.PollCompletedAt.Equal(first.PollCompletedAt) ||
			row.IfIndex == 0 || !counterHistoryMetricName(row.Name) ||
			(row.Width != 32 && row.Width != 64) || (row.Width == 32 && row.Value > 1<<32-1) ||
			(!row.InterfaceSpeedKnown && row.InterfaceSpeedBPS != 0) || (!row.UptimeKnown && row.UptimeTicks != 0) || (!row.DiscontinuityKnown && row.DiscontinuityTicks != 0) {
			return ErrCounterHistoryInput
		}
		key := point{row.IfIndex, row.Name}
		speed := speedWord{row.InterfaceSpeedKnown, row.InterfaceSpeedBPS}
		if prior, found := speeds[row.IfIndex]; found && prior != speed {
			return ErrCounterHistoryInput
		}
		speeds[row.IfIndex] = speed
		if _, duplicate := seen[key]; duplicate {
			return ErrCounterHistoryInput
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateCounterQuery(ctx context.Context, query CounterQuery) error {
	if err := validateCounterTenant(ctx, query.TenantID); err != nil {
		return err
	}
	if !counterClock(query.From) || !counterClock(query.To) || !query.To.After(query.From) || len(query.Sources) == 0 ||
		query.Budget.MemoryBytes <= 0 || query.Budget.WorkUnits <= 0 || query.Budget.Timeout <= 0 {
		return ErrCounterHistoryInput
	}
	budget := query.Budget
	if int64(len(query.Sources)) > budget.MemoryBytes/4096 || int64(len(query.Sources)) > budget.WorkUnits/4096 {
		return ErrCounterHistoryBudget
	}
	type member struct {
		context, device string
		iface           uint32
	}
	seen := make(map[member]struct{})
	for _, selector := range query.Sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateCounterSource(selector.CounterSource); err != nil {
			return err
		}
		if len(selector.IfIndexes) == 0 {
			return ErrCounterHistoryInput
		}
		charge := counterRowCharge(CounterRow{TenantID: query.TenantID, CounterSource: selector.CounterSource})
		if charge <= 0 || charge > budget.MemoryBytes || charge > budget.WorkUnits {
			return ErrCounterHistoryBudget
		}
		budget.MemoryBytes, budget.WorkUnits = budget.MemoryBytes-charge, budget.WorkUnits-charge
		for _, index := range selector.IfIndexes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if budget.MemoryBytes < 512 || budget.WorkUnits < 512 {
				return ErrCounterHistoryBudget
			}
			budget.MemoryBytes, budget.WorkUnits = budget.MemoryBytes-512, budget.WorkUnits-512
			key := member{selector.ContextID, selector.DeviceID, index}
			if index == 0 {
				return ErrCounterHistoryInput
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrCounterHistoryInput
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

func counterRowID(row CounterRow) string {
	// CaptureKey binds the entire original body. This point key collapses
	// exact redelivery without conflating distinct original observations.
	body, _ := json.Marshal(struct {
		Capture [32]byte
		IfIndex uint32
		Name    string
	}{row.CaptureKey, row.IfIndex, row.Name})
	return hex.EncodeToString(crypto.Hash(body))
}

type counterSelectionKey struct {
	context, device, agent, source string
	sourceAt, agentAt              int64
	index                          uint32
}

func counterSelectionKeyFor(source CounterSource, index uint32) counterSelectionKey {
	return counterSelectionKey{source.ContextID, source.DeviceID, source.AgentID, source.SourceRef,
		source.SourceAssignedAt.UnixNano(), source.AgentAssignedAt.UnixNano(), index}
}

// Admission already accounts for the complete selector set. Compile it once
// so a month of observations does constant work per point, not a scan of every
// interface on every device for every historical point.
func compileCounterSelection(query CounterQuery) func(CounterRow) bool {
	selected := make(map[counterSelectionKey]struct{})
	for _, source := range query.Sources {
		for _, index := range source.IfIndexes {
			selected[counterSelectionKeyFor(source.CounterSource, index)] = struct{}{}
		}
	}
	return func(row CounterRow) bool {
		if row.TenantID != query.TenantID || row.PollStartedAt.Before(query.From) || row.PollStartedAt.After(query.To) {
			return false
		}
		_, ok := selected[counterSelectionKeyFor(row.CounterSource, row.IfIndex)]
		return ok
	}
}
