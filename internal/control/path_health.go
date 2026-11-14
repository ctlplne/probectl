// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type pathInterfaceHealth struct {
	Status           string                          `json:"status"`
	ContextID        string                          `json:"context_id,omitempty"`
	InterfaceID      string                          `json:"interface_id,omitempty"`
	DeviceID         string                          `json:"device_id,omitempty"`
	AgentID          string                          `json:"agent_id,omitempty"`
	SourceRef        string                          `json:"source_ref,omitempty"`
	From             time.Time                       `json:"from"`
	To               time.Time                       `json:"to"`
	PhysicalMaxBPS   string                          `json:"physical_max_bps,omitempty"`
	Method           string                          `json:"method"`
	ConfigCoverage   string                          `json:"config_coverage"`
	ConfigChanges    []device.ConfigArchiveReference `json:"config_changes,omitempty"`
	SourceValidUntil *time.Time                      `json:"source_valid_until,omitempty"`
	Counters         []pathHealthCounter             `json:"counters"`
	ErrorTrends      []pathHealthErrorTrend          `json:"error_trends,omitempty"`
}

type pathHealthOptions struct {
	from, to    time.Time
	gap         time.Duration
	physicalMax uint64
}

type pathHealthCheck struct {
	target          store.DeviceCounterInterface
	device, address string
	rows            []flowstore.CounterRow
}

type pathHealthOperation struct {
	op           capacityForecastOperation
	options      pathHealthOptions
	remaining    int64
	checks       []pathHealthCheck
	configChecks []pathConfigCheck
}

func pathHealthRequested(r *http.Request) (bool, error) {
	values := r.URL.Query()["include_health"]
	if len(values) == 0 {
		return false, nil
	}
	if len(values) != 1 {
		return false, apierror.Validation("include_health must be a single boolean")
	}
	value, err := strconv.ParseBool(values[0])
	if err != nil {
		return false, apierror.Validation("include_health must be a boolean")
	}
	return value, nil
}

func parsePathHealthOptions(r *http.Request, now time.Time) (pathHealthOptions, error) {
	value := pathHealthOptions{from: now.Add(-15 * time.Minute), to: now, gap: 5 * time.Minute}
	for key, target := range map[string]*time.Time{"health_from": &value.from, "health_to": &value.to} {
		values := r.URL.Query()[key]
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 {
			return pathHealthOptions{}, apierror.Validation("health bounds must be single timestamps")
		}
		at, err := time.Parse(time.RFC3339Nano, values[0])
		if err != nil || at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
			return pathHealthOptions{}, apierror.Validation("health bounds require supported RFC3339 timestamps")
		}
		*target = at.UTC()
	}
	if values := r.URL.Query()["health_poll_gap"]; len(values) != 0 {
		if len(values) != 1 {
			return pathHealthOptions{}, apierror.Validation("health_poll_gap must be one duration")
		}
		gap, err := time.ParseDuration(values[0])
		if err != nil || gap <= 0 {
			return pathHealthOptions{}, apierror.Validation("health_poll_gap must be a positive duration")
		}
		value.gap = gap
	}
	if values := r.URL.Query()["health_max_bps"]; len(values) != 0 {
		if len(values) != 1 {
			return pathHealthOptions{}, apierror.Validation("health_max_bps must be one positive integer")
		}
		maximum, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil || maximum == 0 || strconv.FormatUint(maximum, 10) != values[0] {
			return pathHealthOptions{}, apierror.Validation("health_max_bps must be a canonical positive uint64")
		}
		value.physicalMax = maximum
	}
	if !value.to.After(value.from) || value.to.After(now) {
		return pathHealthOptions{}, apierror.Validation("health window must end after its start and no later than now")
	}
	return value, nil
}

func (s *Server) beginPathHealth(r *http.Request) (*pathHealthOperation, error) {
	options, err := parsePathHealthOptions(r, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	op, err := s.beginCapacityForecast(r)
	if err != nil {
		return nil, err
	}
	return &pathHealthOperation{op: op, options: options, remaining: op.budget.MemoryBytes}, nil
}

func newPathInterfaceHealth(options pathHealthOptions, status string) *pathInterfaceHealth {
	return &pathInterfaceHealth{Status: status, From: options.from, To: options.to,
		Method: "original_counter_poll_start_mean", ConfigCoverage: "unavailable_no_context_bound_archive",
		Counters: []pathHealthCounter{}}
}

func (s *Server) readPathInterfaceHealth(query *pathHealthOperation, scope entity.Scope, device, address string) (*pathInterfaceHealth, error) {
	options := query.options
	ctx, actor := query.op.request.Context(), query.op.actor
	budget := flowstore.CounterBudget{MemoryBytes: query.remaining, WorkUnits: query.remaining, Timeout: query.op.budget.ExecutionLimit}
	if query.remaining < 8192 {
		return nil, apierror.TooLarge("complete path health exceeds resource admission")
	}
	id, err := store.NewDeviceCounterCaptures(s.pool).CurrentAddressInterface(ctx, scope, device, address)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return newPathInterfaceHealth(options, "interface_unresolved_or_ambiguous"), nil
	}
	selected := capacityCounterSelection{Scope: scope, InterfaceID: id}
	target, err := s.capacityCounterSnapshot(ctx, actor, selected, nil, nil, budget)
	if errors.Is(err, pgx.ErrNoRows) {
		return newPathInterfaceHealth(options, "not_current_polled_interface"), nil
	}
	if err != nil {
		return nil, err
	}
	result := newPathInterfaceHealth(options, "observed_originals")
	result.ContextID, result.InterfaceID, result.DeviceID = scope.ContextID, id, target.Source.DeviceID
	result.AgentID, result.SourceRef = target.Source.AgentID, target.Source.SourceRef
	validUntil := target.ValidUntil
	result.SourceValidUntil = &validUntil
	if options.physicalMax != 0 {
		result.PhysicalMaxBPS = strconv.FormatUint(options.physicalMax, 10)
	}
	history, available := flowstore.CounterHistoryOf(s.flowStore)
	if !available {
		query.checks = append(query.checks, pathHealthCheck{target: target, device: device, address: address})
		result.Status = "counter_history_unavailable"
		return result, nil
	}
	rows, err := history.CounterPoints(ctx, flowstore.CounterQuery{TenantID: actor.TenantID, From: options.from, To: options.to,
		Sources: []flowstore.CounterSelector{{CounterSource: target.Source, IfIndexes: []uint32{target.IfIndex}}}, Budget: budget})
	if err != nil {
		return nil, err // Never calculate over a backend prefix after a late error.
	}
	query.remaining -= 8192
	for _, row := range rows {
		charge := int64(8192)
		for _, value := range []string{row.TenantID, row.ContextID, row.DeviceID, row.AgentID, row.SourceRef, row.SenderSerial} {
			if int64(len(value)) > query.remaining/16 {
				return nil, apierror.TooLarge("complete path health exceeds resource admission")
			}
			charge += int64(len(value)) * 16
		}
		if charge > query.remaining {
			return nil, apierror.TooLarge("complete path health exceeds resource admission")
		}
		query.remaining -= charge
	}
	if _, err := s.capacityCounterSnapshot(ctx, actor, selected, &target, rows, budget); err != nil {
		return nil, err
	}
	result.Counters, err = projectPathHealth(ctx, rows, options.to, options.gap, options.physicalMax)
	if err != nil {
		return nil, err
	}
	result.ErrorTrends, err = projectPathHealthErrorTrends(ctx, rows, options.to, options.gap)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		result.Status = "no_original_observations"
	}
	query.checks = append(query.checks, pathHealthCheck{target: target, device: device, address: address, rows: rows})
	if err := s.readPathConfigReferences(query, target, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Server) populatePathHealth(query *pathHealthOperation, binding store.PathTestBinding, items []pathEntityHop) error {
	ctx := query.op.request.Context()
	if err := s.authorizePathHealth(query, binding.Scope, items); err != nil {
		return err
	}
	cache := map[string]*pathInterfaceHealth{}
	for i := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(len(items)) > query.op.budget.MemoryBytes/4096 {
			return apierror.TooLarge("complete path health exceeds resource admission")
		}
		if items[i].Resolution.Status != entity.Resolved {
			items[i].Health = newPathInterfaceHealth(query.options, "identity_"+string(items[i].Resolution.Status))
			continue
		}
		id := items[i].Resolution.EntityID
		key := id + "\x00" + items[i].IP
		if cached, ok := cache[key]; ok {
			items[i].Health = cached
			continue
		}
		health, err := s.readPathInterfaceHealth(query, binding.Scope, id, items[i].IP)
		if err != nil {
			return err
		}
		cache[key], items[i].Health = health, health
	}
	for _, item := range items {
		body, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if int64(len(body)) > query.remaining/2 {
			return apierror.TooLarge("complete path health exceeds resource admission")
		}
		query.remaining -= int64(len(body)) * 2
	}
	return nil
}

// Refresh the current user and context policy without widening the original
// credential ceiling. Repeat at publication, including path-only permissions.
func (s *Server) authorizePathHealth(query *pathHealthOperation, scope entity.Scope, items []pathEntityHop) error {
	ctx, actor := query.op.request.Context(), query.op.actor
	resource, err := s.entityResource(ctx, scope)
	if err != nil {
		return err
	}
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	for _, permission := range []string{permTestRead, ai.PermEntitiesRead, ai.PermMetricsRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	for _, item := range items {
		if err := s.authorizeEntityResolution(ctx, principal, item.Resolution, resource); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) revalidatePathHealth(query *pathHealthOperation, binding store.PathTestBinding, items []pathEntityHop) error {
	ctx, actor := query.op.request.Context(), query.op.actor
	if err := s.authorizePathHealth(query, binding.Scope, items); err != nil {
		return err
	}
	registry := store.NewEntityRegistry(s.pool)
	current, err := registry.PathTestBinding(ctx, actor.TenantID, query.op.request.PathValue("id"))
	if err != nil || current.Scope != binding.Scope || current.Target != binding.Target || !current.AssignedAt.Equal(binding.AssignedAt) {
		return apierror.Unavailable("path context or target changed; retry")
	}
	addresses := make([]string, 0, len(items))
	for _, item := range items {
		alias, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: item.IP}).Normalize()
		if err == nil {
			addresses = append(addresses, alias.Value)
		}
	}
	resolved, err := registry.ResolveAddressesWithBudget(ctx, binding.Scope, addresses, query.op.budget.MemoryBytes)
	if err != nil {
		return err
	}
	for _, item := range items {
		alias, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: item.IP}).Normalize()
		if err != nil {
			continue
		}
		before, err := json.Marshal(item.Resolution)
		if err != nil {
			return err
		}
		after, err := json.Marshal(resolved[alias.Value])
		if err != nil || !bytes.Equal(before, after) {
			return apierror.Unavailable("path identity changed during health read; retry")
		}
	}
	budget := flowstore.CounterBudget{MemoryBytes: query.op.budget.MemoryBytes, WorkUnits: query.op.budget.MemoryBytes, Timeout: query.op.budget.ExecutionLimit}
	if err := s.revalidatePathConfigReferences(query); err != nil {
		return err
	}
	for _, check := range query.checks {
		id, err := store.NewDeviceCounterCaptures(s.pool).CurrentAddressInterface(ctx, check.target.Scope, check.device, check.address)
		if err != nil || id != check.target.InterfaceID {
			return apierror.Unavailable("path interface address evidence changed; retry")
		}
		selected := capacityCounterSelection{Scope: check.target.Scope, InterfaceID: check.target.InterfaceID}
		if _, err := s.capacityCounterSnapshot(ctx, actor, selected, &check.target, check.rows, budget); err != nil {
			return err
		}
		if !check.target.ValidUntil.After(time.Now().UTC()) {
			return apierror.Unavailable("path health source authority expired; retry")
		}
	}
	return ctx.Err()
}

// REST has the original bearer/session on its request. MCP independently
// refreshes its originating HTTPS/stdio credential after full redaction.
func (s *Server) revalidatePathHealthCredential(query *pathHealthOperation) error {
	actor := query.op.actor
	credential := s.resolvePrincipal(query.op.request)
	if credential == nil {
		return unauthenticated(query.op.request)
	}
	if !auth.SamePrincipalAuthority(actor, credential) {
		return apierror.Forbidden("credential authority changed during path health read")
	}
	return query.op.request.Context().Err()
}

// Preserve domain refusals while keeping storage details out of public errors.
func pathHealthError(err error) error {
	if _, known := apierror.As(err); known {
		return err
	}
	if errors.Is(err, flowstore.ErrCounterHistoryBudget) || errors.Is(err, store.ErrCounterCaptureBudget) {
		return apierror.TooLarge("complete path health exceeds resource admission")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return apierror.Unavailable("path health read did not complete")
	}
	return apierror.Unavailable("complete current path health evidence is unavailable")
}
