// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

type explorerBudgetKey struct{}

func withExplorerBudget(ctx context.Context, budget ExplorerBudget) context.Context {
	return context.WithValue(ctx, explorerBudgetKey{}, budget)
}

func explorerBudgetFor(ctx context.Context) ExplorerBudget {
	if budget, ok := ctx.Value(explorerBudgetKey{}).(ExplorerBudget); ok {
		return budget
	}
	return DefaultExplorerBudget()
}

func selectExplorerBudget(budgets []ExplorerBudget) (ExplorerBudget, error) {
	budget := DefaultExplorerBudget()
	if len(budgets) > 1 {
		return ExplorerBudget{}, errors.New("one flow explorer budget is required")
	}
	if len(budgets) == 1 {
		budget = budgets[0]
	}
	return budget, budget.Validate()
}

// ExplorerOperationBudget lets tenant-scoped metadata readers share the
// captured cost envelope rather than loading a different policy mid-query.
func ExplorerOperationBudget(ctx context.Context, store Store) ExplorerBudget {
	if budget, ok := ctx.Value(explorerBudgetKey{}).(ExplorerBudget); ok {
		return budget
	}
	return ExplorerQueryBudget(store)
}

// AttachExplorerBudget configures trusted cost admission at construction. It
// does not grant a caller any new source or override a tenant read policy.
func AttachExplorerBudget(store Store, budget ExplorerBudget) error {
	if err := budget.Validate(); err != nil {
		return err
	}
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		case *Memory:
			if current == nil {
				return errors.New("flow store is unavailable")
			}
			current.mu.Lock()
			current.explorerBudget = budget
			current.mu.Unlock()
			return nil
		case *ClickHouse:
			if current == nil {
				return errors.New("flow store is unavailable")
			}
			// Like the router and reader policy, configure before serving reads.
			current.explorerBudget = budget
			return nil
		default:
			return errors.New("flow store cannot enforce configured explorer budgets")
		}
	}
}

// ExplorerQueryBudget reports operator admission; an unwired/custom store has
// the existing defaults. Attachment to an unsupported store refuses above.
func ExplorerQueryBudget(store Store) ExplorerBudget {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		case *Memory:
			if current == nil {
				return DefaultExplorerBudget()
			}
			current.mu.Lock()
			budget := current.explorerBudget
			current.mu.Unlock()
			if budget != (ExplorerBudget{}) {
				return budget
			}
			return DefaultExplorerBudget()
		case *ClickHouse:
			if current == nil {
				return DefaultExplorerBudget()
			}
			if current.explorerBudget != (ExplorerBudget{}) {
				return current.explorerBudget
			}
			return DefaultExplorerBudget()
		default:
			return DefaultExplorerBudget()
		}
	}
}

// ExplorerBudget is operator-owned admission, never query grammar. Capture a
// value at operation entry so all source probes, retries and decodes share it.
// Public dimensions, selected rows and time coverage are independent of cost.
type ExplorerBudget struct {
	ExecutionLimit     time.Duration
	ReadBytes          int64
	ReadRows           int
	ResponseBytes      int64
	MemoryBytes        int64
	IntermediateGroups int
	InterfaceItems     int
	Threads            int
}

func DefaultExplorerBudget() ExplorerBudget {
	return ExplorerBudget{
		ExecutionLimit: ExplorerExecutionLimit,
		ReadBytes:      ExplorerReadBytes, ReadRows: ExplorerReadRows,
		ResponseBytes: chclient.MaxResponseBytes, MemoryBytes: 2 << 30,
		IntermediateGroups: planIntermediateLimit,
		InterfaceItems:     ExplorerInterfaceLimit, Threads: 2,
	}
}

// Validate never treats zero as unlimited, and leaves space for sentinel reads
// and interface lookups before conversion to the host's allocation counters.
func (b ExplorerBudget) Validate() error {
	maxInt := int(^uint(0) >> 1)
	if b.ExecutionLimit <= 0 || b.ExecutionLimit > time.Duration(1<<63-1)/6 || b.ReadBytes <= 0 || b.ReadRows <= 0 ||
		b.ResponseBytes <= 0 || b.MemoryBytes <= 0 || b.IntermediateGroups <= 0 ||
		b.InterfaceItems <= 0 || b.Threads <= 0 ||
		b.ReadBytes >= int64(maxInt) || b.ResponseBytes >= int64(maxInt) ||
		b.MemoryBytes >= int64(maxInt) || b.ReadRows == maxInt ||
		b.IntermediateGroups == maxInt || b.InterfaceItems > (maxInt-1)/10 {
		return errors.New("flow explorer cost budgets must be positive and sentinel-safe")
	}
	return nil
}

// settings only emits validated numeric values and fixed overflow policies.
// Filter literals and client metadata cannot contribute SQL structure.
func (b ExplorerBudget) settings() (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	seconds := strconv.FormatInt(int64(b.ExecutionLimit/time.Second), 10)
	if nanos := b.ExecutionLimit % time.Second; nanos != 0 {
		fraction := strconv.FormatInt(int64(nanos)+1_000_000_000, 10)[1:]
		seconds += "." + strings.TrimRight(fraction, "0")
	}
	return "SETTINGS max_execution_time=" + seconds +
		",timeout_overflow_mode='throw',max_bytes_to_read=" + strconv.FormatInt(b.ReadBytes, 10) +
		",max_rows_to_read=" + strconv.Itoa(b.ReadRows) +
		",read_overflow_mode='throw',max_rows_to_group_by=" + strconv.Itoa(b.IntermediateGroups) +
		",group_by_overflow_mode='throw',max_result_rows=" + strconv.Itoa(b.IntermediateGroups) +
		",result_overflow_mode='throw',max_memory_usage=" + strconv.FormatInt(b.MemoryBytes, 10) +
		",max_threads=" + strconv.Itoa(b.Threads), nil
}
