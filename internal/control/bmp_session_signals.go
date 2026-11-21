// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bmpSessionIncidentPublication struct {
	incident *incident.Incident
	opened   bool
}

// BMPSessionSignalWriter correlates only server-derived findings inside the
// original fenced storage transaction. The post-commit observer uses the
// existing notification and SIEM routes.
func BMPSessionSignalWriter(window time.Duration, log *slog.Logger, observer incident.Observer) func(context.Context, tenancy.Scope, []incident.Signal) (func(), error) {
	return func(ctx context.Context, sc tenancy.Scope, signals []incident.Signal) (func(), error) {
		if len(signals) == 0 {
			return nil, nil
		}
		tenant := sc.Tenant.String()
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, tenant); err != nil {
			return nil, err
		}
		publications := make([]bmpSessionIncidentPublication, 0, len(signals))
		var opened bool
		correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, window, log,
			incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
		for _, signal := range signals {
			if signal.TenantID != tenant {
				return nil, entity.ErrScopeMismatch
			}
			found, err := correlator.Ingest(ctx, signal)
			if err != nil {
				return nil, err
			}
			if found == nil || found.ID == "" || found.TenantID != tenant {
				return nil, entity.ErrScopeMismatch
			}
			if err := audit.TenantRecord(ctx, sc, "system", "bgp.session.signal", found.ID, map[string]any{
				"kind": signal.Kind, "observation_digest": signal.Attributes["probectl.bgp.bmp.observation_digest"],
			}); err != nil {
				return nil, err
			}
			publications = append(publications, bmpSessionIncidentPublication{found, opened})
		}
		if observer == nil {
			return nil, nil
		}
		return func() {
			for _, publication := range publications {
				observer(ctx, publication.incident, publication.opened)
			}
		}, nil
	}
}
