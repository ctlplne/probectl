// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func beginNetBoxImport(ctx context.Context, src flowstore.Store, gate *fairness.Gate) (context.Context, flowstore.ExplorerBudget, func(), error) {
	budget := flowstore.ExplorerOperationBudget(ctx, src)
	if err := budget.Validate(); err != nil {
		return nil, budget, nil, apierror.Unavailable("tag import cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, min(budget.ExecutionLimit, 15*time.Second))
	release := func() {}
	if gate != nil {
		tenant, ok := tenancy.FromContext(ctx)
		if !ok {
			cancel()
			return nil, budget, nil, tenancy.ErrNoTenant
		}
		var err error
		release, err = gate.BeginQuery(ctx, tenant.String())
		if err != nil {
			cancel()
			return nil, budget, nil, err
		}
	}
	return ctx, budget, func() { release(); cancel() }, nil
}

func readNetBoxTagTarget(ctx context.Context, pool *pgxpool.Pool, contextID, tagID string, ref store.TagSubjectReference, maxBytes int64) (store.NetBoxTagTarget, store.TagImportFacts, error) {
	var target store.NetBoxTagTarget
	var facts store.TagImportFacts
	err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		target, facts, err = (store.TagAssignments{}).NetBoxSubjectTarget(ctx, sc, contextID, tagID, ref, maxBytes)
		return err
	})
	return target, facts, err
}

func netBoxTargetReference(target store.NetBoxTagTarget) store.TagSubjectReference {
	ref := store.TagSubjectReference{Kind: target.TargetKind, ID: target.TargetID, ExporterAgentID: target.ExporterAgentID, ExporterSourceRef: target.ExporterSourceRef}
	if ref.Kind == "exporter" {
		ref.ID = ""
	}
	return ref
}

func sourceTagFacts(facts store.TagImportFacts) cmdb.NetBoxTagFacts {
	return cmdb.NetBoxTagFacts{Addresses: facts.Addresses, Prefix: facts.Prefix, Hostname: facts.Hostname}
}

func netBoxImportResponseBudget(result any, budget flowstore.ExplorerBudget) error {
	encoded, err := json.Marshal(result)
	if err != nil || int64(len(encoded)) > budget.ResponseBytes || int64(len(encoded)) > budget.MemoryBytes/2 {
		return apierror.Validation("tag import preview exceeds the query response budget")
	}
	return nil
}
