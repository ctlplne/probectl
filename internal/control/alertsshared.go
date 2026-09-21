// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// sharedAlertStore is the persistence behind the replica-independent alert
// state (DPR-067). The evaluator leader publishes the active set and its
// heartbeat; operator actions and maintenance windows are the persisted
// alert_ops / alert_maintenance rows the leader pulls in on every pass.
type sharedAlertStore interface {
	ListActive(ctx context.Context, tenant string) ([]alert.ActiveAlert, error)
	Status(ctx context.Context, tenant string) (evaluatedAt time.Time, interval time.Duration, ok bool, err error)
	ListOps(ctx context.Context, tenant string) ([]store.AlertOp, error)
	UpsertOp(ctx context.Context, tenant string, op store.AlertOp) error
	DeleteOp(ctx context.Context, tenant, fingerprint string) error
	ListMaintenance(ctx context.Context, tenant string) ([]alert.MaintenanceWindow, error)
	UpsertMaintenance(ctx context.Context, tenant string, w alert.MaintenanceWindow) error
	DeleteMaintenance(ctx context.Context, tenant, id string) error
}

// pgSharedAlertStore is the Postgres implementation: every call runs through
// InTenant, so the tenant boundary is enforced by forced RLS, never by the
// handler.
type pgSharedAlertStore struct{ pool *pgxpool.Pool }

func (p pgSharedAlertStore) in(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool, fn)
}

func (p pgSharedAlertStore) ListActive(ctx context.Context, tenant string) (out []alert.ActiveAlert, err error) {
	err = p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		out, err = (store.AlertActiveState{}).List(ctx, sc)
		return err
	})
	return out, err
}

func (p pgSharedAlertStore) Status(ctx context.Context, tenant string) (at time.Time, interval time.Duration, ok bool, err error) {
	err = p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		at, interval, ok, err = (store.AlertActiveState{}).Status(ctx, sc)
		return err
	})
	return at, interval, ok, err
}

func (p pgSharedAlertStore) ListOps(ctx context.Context, tenant string) (out []store.AlertOp, err error) {
	err = p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		out, err = (store.AlertOps{}).List(ctx, sc)
		return err
	})
	return out, err
}

func (p pgSharedAlertStore) UpsertOp(ctx context.Context, tenant string, op store.AlertOp) error {
	return p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error { return (store.AlertOps{}).Upsert(ctx, sc, op) })
}

func (p pgSharedAlertStore) DeleteOp(ctx context.Context, tenant, fingerprint string) error {
	return p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertOps{}).Delete(ctx, sc, fingerprint)
	})
}

func (p pgSharedAlertStore) ListMaintenance(ctx context.Context, tenant string) (out []alert.MaintenanceWindow, err error) {
	err = p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		out, err = (store.AlertMaintenance{}).List(ctx, sc)
		return err
	})
	return out, err
}

func (p pgSharedAlertStore) UpsertMaintenance(ctx context.Context, tenant string, w alert.MaintenanceWindow) error {
	return p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertMaintenance{}).Upsert(ctx, sc, w)
	})
}

func (p pgSharedAlertStore) DeleteMaintenance(ctx context.Context, tenant, id string) error {
	return p.in(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertMaintenance{}).Delete(ctx, sc, id)
	})
}

// persistedAlertState serves a tenant's alert state from the shared store on a
// replica that is not the evaluator leader (DPR-067). Reads overlay the
// persisted operator state onto the published active set; silences and
// acknowledgements are written to alert_ops, which the leader applies on its
// next pass (at most one evaluation interval later).
type persistedAlertState struct {
	store   sharedAlertStore
	tenant  string
	now     func() time.Time
	timeout time.Duration
	log     *slog.Logger
}

func newPersistedAlertState(st sharedAlertStore, tenant string, log *slog.Logger) *persistedAlertState {
	if log == nil {
		log = slog.Default()
	}
	return &persistedAlertState{store: st, tenant: tenant, now: time.Now, timeout: 5 * time.Second, log: log}
}

func (p *persistedAlertState) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout)
}

// Running reports whether the evaluator leader published for this tenant
// recently (within three evaluation intervals).
func (p *persistedAlertState) Running() bool {
	ctx, cancel := p.ctx()
	defer cancel()
	at, interval, ok, err := p.store.Status(ctx, p.tenant)
	if err != nil {
		p.log.Warn("alert shared state: heartbeat read failed", "tenant", p.tenant, "error", err.Error())
		return false
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return ok && p.now().Sub(at) < 3*interval
}

func (p *persistedAlertState) Active() []alert.ActiveAlert {
	ctx, cancel := p.ctx()
	defer cancel()
	items, err := p.store.ListActive(ctx, p.tenant)
	if err != nil {
		p.log.Warn("alert shared state: active read failed", "tenant", p.tenant, "error", err.Error())
		return []alert.ActiveAlert{}
	}
	ops, err := p.store.ListOps(ctx, p.tenant)
	if err != nil {
		p.log.Warn("alert shared state: ops read failed", "tenant", p.tenant, "error", err.Error())
	}
	byFP := make(map[string]store.AlertOp, len(ops))
	for _, op := range ops {
		byFP[op.Fingerprint] = op
	}
	now := p.now()
	out := make([]alert.ActiveAlert, 0, len(items))
	for _, a := range items {
		if op, ok := byFP[a.Fingerprint]; ok {
			if op.SilencedUntil != nil && op.SilencedUntil.After(now) {
				t := *op.SilencedUntil
				a.SilencedUntil = &t
			}
			if op.AckedBy != "" {
				a.AckedBy = op.AckedBy
				a.AckedAt = op.AckedAt
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.After(out[j].Since)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func (p *persistedAlertState) find(fingerprint string) (alert.ActiveAlert, error) {
	for _, a := range p.Active() {
		if a.Fingerprint == fingerprint {
			return a, nil
		}
	}
	return alert.ActiveAlert{}, alert.ErrNotActive
}

func (p *persistedAlertState) Silence(fingerprint string, d time.Duration) (alert.ActiveAlert, error) {
	if d < 0 || d > alert.MaxSilence {
		return alert.ActiveAlert{}, fmt.Errorf("alert: silence duration must be between 0 and %s", alert.MaxSilence)
	}
	a, err := p.find(fingerprint)
	if err != nil {
		return alert.ActiveAlert{}, err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	if d == 0 {
		a.SilencedUntil = nil
		if a.AckedBy == "" {
			return a, p.store.DeleteOp(ctx, p.tenant, fingerprint)
		}
	} else {
		until := p.now().Add(d)
		a.SilencedUntil = &until
	}
	return a, p.store.UpsertOp(ctx, p.tenant, store.AlertOp{
		Fingerprint: a.Fingerprint, RuleID: a.RuleID, SilencedUntil: a.SilencedUntil, AckedBy: a.AckedBy, AckedAt: a.AckedAt,
	})
}

func (p *persistedAlertState) Acknowledge(fingerprint, by string) (alert.ActiveAlert, error) {
	if by == "" {
		by = "unknown"
	}
	a, err := p.find(fingerprint)
	if err != nil {
		return alert.ActiveAlert{}, err
	}
	at := p.now()
	a.AckedBy, a.AckedAt = by, &at
	ctx, cancel := p.ctx()
	defer cancel()
	return a, p.store.UpsertOp(ctx, p.tenant, store.AlertOp{
		Fingerprint: a.Fingerprint, RuleID: a.RuleID, SilencedUntil: a.SilencedUntil, AckedBy: a.AckedBy, AckedAt: a.AckedAt,
	})
}

func (p *persistedAlertState) MaintenanceWindows() []alert.MaintenanceWindow {
	ctx, cancel := p.ctx()
	defer cancel()
	windows, err := p.store.ListMaintenance(ctx, p.tenant)
	if err != nil {
		p.log.Warn("alert shared state: maintenance read failed", "tenant", p.tenant, "error", err.Error())
		return []alert.MaintenanceWindow{}
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i].ID < windows[j].ID })
	return windows
}

func (p *persistedAlertState) UpsertMaintenanceWindow(w alert.MaintenanceWindow) (alert.MaintenanceWindow, error) {
	if w.ID == "" {
		w.ID = guuid.NewString()
	}
	if err := w.Validate(); err != nil {
		return alert.MaintenanceWindow{}, err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	return w, p.store.UpsertMaintenance(ctx, p.tenant, w)
}

func (p *persistedAlertState) DeleteMaintenanceWindow(id string) bool {
	ctx, cancel := p.ctx()
	defer cancel()
	for _, w := range p.MaintenanceWindows() {
		if w.ID == id {
			return p.store.DeleteMaintenance(ctx, p.tenant, id) == nil
		}
	}
	return false
}

func (p *persistedAlertState) PreviewMaintenance(rule alert.Rule, labels map[string]string, from, to time.Time) []alert.MaintenancePreview {
	return alert.PreviewWindows(p.MaintenanceWindows(), rule, labels, from, to)
}

// alertStateRunning is the honest evaluator_running: engine truth on the
// leader, the published heartbeat everywhere else.
func alertStateRunning(src any) bool {
	if src == nil {
		return false
	}
	if r, ok := src.(interface{ Running() bool }); ok {
		return r.Running()
	}
	return true
}
