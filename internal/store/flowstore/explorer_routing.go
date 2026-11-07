// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrRoutingQueryScope = errors.New("flow routing lookup requires current tenant context and source authority")

// RoutingProjection is selected by the current-authority reader, never query
// JSON. Empty values represent unavailable/ambiguous metadata without removing
// any traffic. Complete path sets use a canonical JSON array of full paths.
type RoutingProjection struct {
	entity.Scope
	Key       [32]byte
	Clock     int64
	Fields    map[string]string
	SourceIDs []string
	// FactsID is a request-local memoization hint supplied by the verified
	// capture reader. A matching hint still requires identical context,
	// fields and sources. It never grants or replaces source authority.
	FactsID [32]byte
}

type routingQueryKey struct {
	key   [32]byte
	clock int64
}

type routingQueryData struct {
	tenant string
	asOf   time.Time
	byKey  map[routingQueryKey][32]byte
	facts  map[[32]byte]routingQueryFact
	digest string
}

type routingQueryFact struct {
	Scope     entity.Scope
	Fields    map[string]string
	SourceIDs []string
}

type routingQueryBuilder struct {
	data      *routingQueryData
	remaining int64
	hints     map[[32]byte][32]byte
	seen      map[[32]byte]bool
}

func newRoutingQueryData(ctx context.Context, tenant string, at time.Time, rows []RoutingProjection, memory int64) (*routingQueryData, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !validTagProjectionID(tenant) || at.IsZero() {
		return nil, ErrRoutingQueryScope
	}
	if memory < 4096 || int64(len(rows)) > (memory-4096)/512 {
		return nil, ErrExplorerBudget
	}
	builder := routingQueryBuilder{data: &routingQueryData{tenant: tenant, asOf: at.UTC(), byKey: map[routingQueryKey][32]byte{}, facts: map[[32]byte]routingQueryFact{}}, remaining: memory - 4096, hints: map[[32]byte][32]byte{}, seen: map[[32]byte]bool{}}
	for _, row := range rows {
		if err := builder.add(ctx, row); err != nil {
			return nil, err
		}
	}
	return builder.finish(ctx)
}

func (builder *routingQueryBuilder) charge(bytes int64) error {
	if bytes < 0 || bytes > builder.remaining {
		return ErrExplorerBudget
	}
	builder.remaining -= bytes
	return nil
}

func (builder *routingQueryBuilder) add(ctx context.Context, row RoutingProjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, err := row.Normalize()
	if err != nil || scope != row.Scope || row.TenantID != builder.data.tenant || row.Key == ([32]byte{}) || row.Clock <= 0 || len(row.SourceIDs) == 0 || builder.seen[row.Key] {
		return ErrRoutingQueryScope
	}
	if err := builder.charge(512); err != nil {
		return err
	}
	if int64(len(row.SourceIDs)) > builder.remaining/32 {
		return ErrExplorerBudget
	}
	row.SourceIDs = slices.Clone(row.SourceIDs)
	slices.Sort(row.SourceIDs)
	row.SourceIDs = slices.Compact(row.SourceIDs)
	factID, err := builder.internFact(ctx, row)
	if err != nil {
		return err
	}
	builder.seen[row.Key] = true
	builder.data.byKey[routingQueryKey{row.Key, row.Clock}] = factID
	return nil
}

func (builder *routingQueryBuilder) internFact(ctx context.Context, row RoutingProjection) ([32]byte, error) {
	if row.FactsID != ([32]byte{}) {
		if id, exists := builder.hints[row.FactsID]; exists {
			fact := builder.data.facts[id]
			if fact.Scope != row.Scope || !maps.Equal(fact.Fields, row.Fields) || !slices.Equal(fact.SourceIDs, row.SourceIDs) {
				return [32]byte{}, ErrRoutingQueryScope
			}
			return id, nil
		}
	}
	cost := int64(0)
	for name, value := range row.Fields {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, err
		}
		definition, ok := flow.RoutingQueryField(name)
		if !ok {
			return [32]byte{}, ErrRoutingQueryScope
		}
		cost += 256 + int64(len(name)+len(value))*12
		if cost > builder.remaining {
			return [32]byte{}, ErrExplorerBudget
		}
		if definition.Type == flow.QueryUnsigned && value != "" {
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil || strconv.FormatUint(parsed, 10) != value {
				return [32]byte{}, ErrRoutingQueryScope
			}
		}
		if err := validateRoutingFieldValue(name, value); err != nil {
			return [32]byte{}, err
		}
	}
	for _, source := range row.SourceIDs {
		if source == "" || !utf8.ValidString(source) || strings.ContainsAny(source, "\x00\r\n") {
			return [32]byte{}, ErrRoutingQueryScope
		}
		cost += 256 + int64(len(source))*12
		if cost > builder.remaining {
			return [32]byte{}, ErrExplorerBudget
		}
	}
	fact := routingQueryFact{Scope: row.Scope, Fields: maps.Clone(row.Fields), SourceIDs: slices.Clone(row.SourceIDs)}
	// The source reader supplies stable, complete source order. Preserve it in
	// the hint comparison and canonicalize only the content-addressed payload.
	body, err := json.Marshal(fact)
	if err != nil {
		return [32]byte{}, err
	}
	var id [32]byte
	copy(id[:], crypto.Hash(body))
	if previous, exists := builder.data.facts[id]; exists {
		if previous.Scope != fact.Scope || !maps.Equal(previous.Fields, fact.Fields) || !slices.Equal(previous.SourceIDs, fact.SourceIDs) {
			return [32]byte{}, ErrRoutingQueryScope
		}
	} else {
		if err := builder.charge(cost); err != nil {
			return [32]byte{}, err
		}
		builder.data.facts[id] = fact
	}
	if row.FactsID != ([32]byte{}) {
		builder.hints[row.FactsID] = id
	}
	return id, nil
}

func validateRoutingFieldValue(name, value string) error {
	if !utf8.ValidString(value) {
		return ErrRoutingQueryScope
	}
	switch {
	case strings.HasSuffix(name, "_provenance"):
		switch value {
		case "router_selected", "public_ris", "public_routeviews", "no_prefix", "unavailable", "ambiguous":
			return nil
		default:
			return ErrRoutingQueryScope
		}
	case strings.HasSuffix(name, "_rpki"):
		switch value {
		case "valid", "invalid", "not_found", "unknown":
			return nil
		default:
			return ErrRoutingQueryScope
		}
	case strings.HasSuffix(name, "_prefix") && value != "":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return ErrRoutingQueryScope
		}
	case strings.HasSuffix(name, "_as_paths") && value != "":
		var paths []string
		if err := json.Unmarshal([]byte(value), &paths); err != nil || len(paths) == 0 {
			return ErrRoutingQueryScope
		}
		canonical, err := json.Marshal(paths)
		if err != nil || string(canonical) != value {
			return ErrRoutingQueryScope
		}
	}
	return nil
}

func (builder *routingQueryBuilder) finish(ctx context.Context) (*routingQueryData, error) {
	type reference struct {
		Key   [32]byte
		Clock int64
		Fact  [32]byte
	}
	refs := make([]reference, 0, len(builder.data.byKey))
	for key, fact := range builder.data.byKey {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		refs = append(refs, reference{key.key, key.clock, fact})
	}
	slices.SortFunc(refs, func(a, b reference) int { return slices.Compare(a.Key[:], b.Key[:]) })
	body, err := json.Marshal(struct {
		Tenant     string
		References []reference
	}{builder.data.tenant, refs})
	if err != nil {
		return nil, err
	}
	// Per-reference reservation includes this compact serialization. Full
	// fields were charged only once per unique content-addressed fact.
	builder.data.digest = hex.EncodeToString(crypto.Hash(body))
	return builder.data, nil
}

func (data *routingQueryData) validate(ctx context.Context, tenant string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if data == nil || !ok || bound.String() != tenant || data.tenant != tenant || data.asOf.IsZero() || data.digest == "" {
		return ErrRoutingQueryScope
	}
	return nil
}

func planUsesRouting(plan flow.QueryPlan) bool {
	for _, names := range [][]string{plan.GroupBy, plan.MatrixWith, flow.QueryFilterFields(plan.Filter)} {
		for _, name := range names {
			if _, ok := flow.RoutingQueryField(name); ok {
				return true
			}
		}
	}
	return false
}

func validatePlanRouting(ctx context.Context, query PlanQuery, plan flow.QueryPlan) error {
	if !planUsesRouting(plan) {
		return nil
	}
	return query.Routing.validate(ctx, query.TenantID)
}

func (data *routingQueryData) valueForRow(row Row, field string) string {
	if data == nil || row.TenantID != data.tenant || row.RoutingCaptureKey == "" {
		return routingMissingField(field)
	}
	if err := validateRoutingCaptureRow(row); err != nil {
		return routingMissingField(field)
	}
	body, _ := hex.DecodeString(row.RoutingCaptureKey)
	var key [32]byte
	copy(key[:], body)
	if id, exists := data.byKey[routingQueryKey{key, row.RoutingCapturedUnixNanos}]; exists {
		if value, exists := data.facts[id].Fields[field]; exists {
			return value
		}
	}
	return routingMissingField(field)
}

func routingMissingField(field string) string {
	for _, side := range []string{"src", "dst"} {
		switch field {
		case side + "_bgp_provenance":
			return "unavailable"
		case side + "_bgp_rpki":
			return "unknown"
		}
	}
	return ""
}

func (data *routingQueryData) externalData(ctx context.Context, tenant string, memory int64) ([]explorerExternalData, error) {
	if err := data.validate(ctx, tenant); err != nil {
		return nil, err
	}
	if memory <= 0 || int64(len(data.byKey)) > memory/256 {
		return nil, ErrExplorerBudget
	}
	keys := make([]routingQueryKey, 0, len(data.byKey))
	for key := range data.byKey {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b routingQueryKey) int { return slices.Compare(a.key[:], b.key[:]) })
	var references, facts bytes.Buffer
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fact := data.byKey[key]
		body, err := json.Marshal(struct {
			Tenant string `json:"routing_ref_tenant"`
			Key    string `json:"routing_key"`
			Clock  string `json:"routing_clock"`
			Fact   string `json:"routing_fact"`
		}{tenant, hex.EncodeToString(key.key[:]), strconv.FormatInt(key.clock, 10), hex.EncodeToString(fact[:])})
		if err != nil {
			return nil, err
		}
		if int64(len(body)+1) > memory {
			return nil, ErrExplorerBudget
		}
		memory -= int64(len(body) + 1)
		references.Write(body)
		references.WriteByte('\n')
	}
	ids := make([][32]byte, 0, len(data.facts))
	for id := range data.facts {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b [32]byte) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fact := data.facts[id]
		if fact.Scope.TenantID != tenant {
			return nil, ErrRoutingQueryScope
		}
		cost := int64(512)
		for name, value := range fact.Fields {
			cost += int64(len(name)+len(value)) * 12
			if cost > memory {
				return nil, ErrExplorerBudget
			}
		}
		body, err := json.Marshal(struct {
			Tenant string            `json:"routing_fact_tenant"`
			ID     string            `json:"routing_fact_id"`
			Fields map[string]string `json:"routing_values"`
		}{tenant, hex.EncodeToString(id[:]), fact.Fields})
		if err != nil {
			return nil, err
		}
		if int64(len(body)+1) > memory {
			return nil, ErrExplorerBudget
		}
		memory -= int64(len(body) + 1)
		facts.Write(body)
		facts.WriteByte('\n')
	}
	return []explorerExternalData{{kind: externalRoutingReferences, rows: references.Bytes()}, {kind: externalRoutingFacts, rows: facts.Bytes()}}, nil
}

func planRoutingJoinsSQL(from string, plan flow.QueryPlan) string {
	if !planUsesRouting(plan) {
		return from
	}
	return from + " ANY LEFT JOIN routing_capture_lookup AS routing_refs ON routing_refs.routing_ref_tenant=tenant_id AND routing_refs.routing_key=routing_capture_key AND routing_refs.routing_clock=routing_captured_unix_nanos" +
		" ANY LEFT JOIN routing_fact_lookup AS routing_meta ON routing_meta.routing_fact_tenant=tenant_id AND routing_meta.routing_fact_id=routing_refs.routing_fact"
}
