// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type explorerBatchKey struct{}
type explorerBatchOwnerKey struct{}

// PlanBatch is one tenant's serial, request-local source operation. It grants
// no source access. The caller owns authorization and one fairness admission.
// Every returned result remains provisional until the entire batch succeeds.
type PlanBatch struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	backend                  PlanStore
	tenant                   string
	budget                   ExplorerBudget
	queryMu                  sync.Mutex
	costMu                   sync.Mutex
	queries                  int
	failed                   bool
	readRows                 int
	readBytes, responseBytes int64
}

// NewPlanBatch captures the operator policy once and shares one deadline.
// Declared plans reserve their share of retained result/workspace allocations;
// reads consume one cumulative envelope, including probes and retries.
func NewPlanBatch(ctx context.Context, store Store, tenant string, plans int) (*PlanBatch, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || tenant == "" {
		return nil, ErrNoTenant
	}
	if ctx.Value(explorerBatchOwnerKey{}) != nil {
		return nil, ErrExplorerBudget
	}
	backend, ok := PlanStoreOf(store)
	if !ok {
		return nil, ErrExplorerBudget
	}
	switch current := backend.(type) {
	case *Memory:
		if current == nil {
			return nil, ErrExplorerBudget
		}
	case *ClickHouse:
		if current == nil {
			return nil, ErrExplorerBudget
		}
	default:
		return nil, ErrExplorerBudget
	}
	budget := ExplorerQueryBudget(store)
	if err := budget.Validate(); err != nil || plans <= 0 {
		return nil, ErrExplorerBudget
	}
	allocated := budget
	allocated.MemoryBytes /= int64(plans)
	allocated.ResponseBytes /= int64(plans)
	allocated.IntermediateGroups /= plans
	allocated.InterfaceItems /= plans
	if err := allocated.Validate(); err != nil {
		return nil, ErrExplorerBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	b := &PlanBatch{cancel: cancel, backend: backend, tenant: tenant, budget: allocated,
		queries: plans, readRows: budget.ReadRows, readBytes: budget.ReadBytes, responseBytes: budget.ResponseBytes}
	b.ctx = withExplorerBudget(context.WithValue(ctx, explorerBatchOwnerKey{}, b), allocated)
	return b, nil
}

// Context also binds metadata reads to the captured cost policy and deadline.
func (b *PlanBatch) Context() context.Context { return b.ctx }

func (b *PlanBatch) Close() { b.cancel() }

func (b *PlanBatch) queryContext() context.Context {
	return context.WithValue(b.ctx, explorerBatchKey{}, b)
}

func (b *PlanBatch) ExplorePlan(query PlanQuery) (PlanResult, error) {
	b.queryMu.Lock()
	defer b.queryMu.Unlock()
	if err := b.ctx.Err(); err != nil {
		return PlanResult{}, err
	}
	if b.failed || b.queries == 0 {
		return PlanResult{}, ErrExplorerBudget
	}
	if query.TenantID != b.tenant {
		b.failed = true
		return PlanResult{}, ErrNoTenant
	}
	b.queries--
	result, err := b.backend.ExplorePlan(b.queryContext(), query)
	if err != nil {
		b.failed = true
		return PlanResult{}, err
	}
	return result, nil
}

func explorerPlanBudget(ctx context.Context, backend PlanStore, tenant string, store Store) (ExplorerBudget, error) {
	b, _ := ctx.Value(explorerBatchKey{}).(*PlanBatch)
	if b == nil {
		if ctx.Value(explorerBatchOwnerKey{}) != nil {
			return ExplorerBudget{}, ErrExplorerBudget
		}
		budget := ExplorerQueryBudget(store)
		return budget, budget.Validate()
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || b.tenant != tenant || b.backend != backend {
		return ExplorerBudget{}, ErrNoTenant
	}
	return b.budget, b.budget.Validate()
}

func chargeBatchRead(ctx context.Context, tenant string, rows int, bytes int64) error {
	b, _ := ctx.Value(explorerBatchKey{}).(*PlanBatch)
	if b == nil {
		return nil
	}
	b.costMu.Lock()
	defer b.costMu.Unlock()
	if b.tenant != tenant {
		return ErrNoTenant
	}
	if rows < 0 || bytes < 0 || rows > b.readRows || bytes > b.readBytes {
		return ErrExplorerBudget
	}
	b.readRows -= rows
	b.readBytes -= bytes
	return nil
}

func batchQueryLimits(ctx context.Context, tenant, sql string) (string, int64, error) {
	budget := explorerBudgetFor(ctx)
	b, _ := ctx.Value(explorerBatchKey{}).(*PlanBatch)
	if b == nil {
		return sql, budget.ResponseBytes, nil
	}
	b.costMu.Lock()
	defer b.costMu.Unlock()
	if tenant != b.tenant {
		return "", 0, ErrNoTenant
	}
	base, err := budget.settings()
	if err != nil || !strings.HasSuffix(sql, base) {
		return "", 0, ErrExplorerBudget
	}
	budget.ReadRows = min(budget.ReadRows, b.readRows)
	budget.ReadBytes = min(budget.ReadBytes, b.readBytes)
	budget.ResponseBytes = min(budget.ResponseBytes, b.responseBytes)
	limited, err := budget.settings()
	if err != nil {
		return "", 0, ErrExplorerBudget
	}
	return strings.TrimSuffix(sql, base) + limited, budget.ResponseBytes, nil
}

func chargeBatchResponse(ctx context.Context, tenant string, header http.Header, size int64) error {
	b, _ := ctx.Value(explorerBatchKey{}).(*PlanBatch)
	if b == nil {
		return nil
	}
	values := header.Values("X-ClickHouse-Summary")
	if len(values) != 1 || len(values[0]) > 4096 {
		return ErrExplorerBudget
	}
	summary, err := parseBatchSummary(values[0])
	if err != nil {
		return ErrExplorerBudget
	}
	rows, err := strconv.Atoi(summary["read_rows"])
	if err != nil || rows < 0 || strconv.Itoa(rows) != summary["read_rows"] {
		return ErrExplorerBudget
	}
	bytes, err := strconv.ParseInt(summary["read_bytes"], 10, 64)
	if err != nil || bytes < 0 || strconv.FormatInt(bytes, 10) != summary["read_bytes"] {
		return ErrExplorerBudget
	}
	if err := chargeBatchRead(ctx, tenant, rows, bytes); err != nil {
		return err
	}
	b.costMu.Lock()
	defer b.costMu.Unlock()
	if size < 0 || size > b.responseBytes {
		return ErrExplorerBudget
	}
	b.responseBytes -= size
	return nil
}

func parseBatchSummary(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	decoder := json.NewDecoder(strings.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrExplorerBudget
	}
	seen := map[string]bool{}
	values := map[string]string{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return nil, ErrExplorerBudget
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrExplorerBudget
		}
		if name == "read_rows" || name == "read_bytes" {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return nil, ErrExplorerBudget
			}
			values[name] = text
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.InputOffset() != int64(len(raw)) {
		return nil, ErrExplorerBudget
	}
	return values, nil
}
