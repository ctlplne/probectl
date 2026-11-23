// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

const pathChangeSource = "probectl-path"
const pathChangeHistoryBytes = 8 << 20
const maxTrackedPathVantages = 16

var localPathHostname, _ = os.Hostname()

var errPathChangeStateMoved = errors.New("path change state moved")

type pathChangeState struct {
	TestRevision time.Time `json:"test_revision"`
	Vantage      string    `json:"vantage"`
	Baseline     string    `json:"baseline"`
	Candidate    string    `json:"candidate,omitempty"`
	LastStart    time.Time `json:"last_start"`
	LastComplete time.Time `json:"last_complete"`
}

// WithPathChangeObserver delivers confirmed incidents through the existing
// notification observer after the timeline, state and incident commit.
func (s *Server) WithPathChangeObserver(observer incident.Observer) *Server {
	s.pathChangeObserver = observer
	return s
}

func (s *Server) observePathChange(r *http.Request, test *store.Test, id, vantage string, started, completed time.Time) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	for range 3 {
		err := s.advancePathChanges(r, test, id, vantage, started, completed)
		if errors.Is(err, errPathChangeStateMoved) {
			continue
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.log.Warn("path change evaluation unavailable", "tenant_id", test.TenantID, "test_id", test.ID)
		}
		return
	}
	s.log.Warn("path change evaluation conflicted", "tenant_id", test.TenantID, "test_id", test.ID)
}

func (s *Server) advancePathChanges(r *http.Request, test *store.Test, id, vantage string, started, completed time.Time) error {
	if localPathHostname == "" || test.TenantID == "" {
		return errors.New("local path vantage unavailable")
	}
	// Replicas can trace different routes. Keep an independent lineage under
	// a tenant-specific digest without exposing the control-plane hostname.
	key := hex.EncodeToString(crypto.Hash([]byte(test.TenantID + "\x00" + vantage + "\x00" + localPathHostname)))
	var previous []byte
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT coalesce(path_change_state, 'null'::jsonb)::text FROM tests
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3`, sc.Tenant.String(), test.ID, test.UpdatedAt).Scan(&previous)
	})
	if err != nil {
		return err
	}
	var byVantage map[string]pathChangeState
	if len(previous) > 16<<10 || json.Unmarshal(previous, &byVantage) != nil || len(byVantage) > maxTrackedPathVantages {
		return errors.New("invalid path change state")
	}
	if byVantage == nil {
		byVantage = map[string]pathChangeState{}
	}
	state, exists := byVantage[key]
	if !exists && len(byVantage) == maxTrackedPathVantages {
		var oldest string
		for candidate, snapshot := range byVantage {
			if oldest == "" || snapshot.LastStart.Before(byVantage[oldest].LastStart) {
				oldest = candidate
			}
		}
		delete(byVantage, oldest)
	}
	if state.Vantage != vantage || !state.TestRevision.Equal(test.UpdatedAt) {
		state = pathChangeState{Vantage: vantage, TestRevision: test.UpdatedAt}
	}
	if !started.After(state.LastStart) || started.Before(state.LastComplete) {
		return nil
	}
	ids := []string{id}
	for _, requested := range []string{state.Baseline, state.Candidate} {
		if requested != "" {
			ids = append(ids, requested)
		}
	}
	// Reading the exact identifiers through the normal tenant reader also
	// confirms that the asynchronous write made it past the lifecycle fence.
	tenantCtx := tenancy.WithTenant(r.Context(), tenancy.ID(test.TenantID))
	retained, err := s.pathStore.History(tenantCtx, test.TenantID, pathHost(test.Target), pathstore.HistoryQuery{IDs: ids, MaxBytes: pathChangeHistoryBytes})
	if err != nil {
		return err
	}
	var origin func(netip.Addr) uint32
	if index := s.openDataEnricher.LocalASNIndex(); index != nil {
		origin = index.Origin
	}
	rounds := make(map[string]path.ChangeRound, len(retained))
	for _, original := range retained {
		if original.CompletedAt == nil || !original.TrustedDiscoveryTime || original.ObservedAt.Before(test.UpdatedAt) {
			continue
		}
		if original.ID == id && (!original.ObservedAt.Equal(started) || !original.CompletedAt.Equal(completed)) {
			return errors.New("retained path clocks changed")
		}
		stampPathVantage(&original.Path)
		if round, ok := path.NewChangeRound(&original.Path, origin); ok {
			rounds[original.ID] = round
		}
	}
	current, ok := rounds[id]
	if !ok {
		return errors.New("current path round is unavailable")
	}
	next := state
	next.LastStart, next.LastComplete = started, completed
	baseline := rounds[state.Baseline]
	if !baseline.Comparable(current) {
		next.Baseline, next.Candidate = id, ""
		byVantage[key] = next
		return s.commitPathChange(r, test, previous, byVantage, nil)
	}
	_, minLatencyMS := testspec.PathChangeOptions(test.Params)
	changes := path.ConfirmChanges(baseline, rounds[state.Candidate], current, minLatencyMS)
	next.Candidate = id
	if changes.Empty() {
		byVantage[key] = next
		return s.commitPathChange(r, test, previous, byVantage, nil)
	}
	next.Baseline, next.Candidate = id, ""
	byVantage[key] = next
	attrs := map[string]string{
		"test_id": test.ID, "vantage": vantage, "vantage_id": key, "baseline_round_id": state.Baseline,
		"candidate_round_id": state.Candidate, "confirmed_round_id": id,
		"confidence": "confirmed", "confirmation_rounds": "2",
		"changed_hops": fmt.Sprint(len(changes.HopTTLs)), "changed_origins": fmt.Sprint(len(changes.OriginTTLs)),
		"changed_latency_segments": fmt.Sprint(len(changes.LatencySegments)),
	}
	event := change.Event{Source: pathChangeSource, Kind: change.KindRoute, Title: "Path change confirmed",
		Summary: fmt.Sprintf("Two rounds confirmed changes at %d hop positions, %d ASN positions and %d latency segments.",
			len(changes.HopTTLs), len(changes.OriginTTLs), len(changes.LatencySegments)),
		Ref: test.ID, Attributes: attrs, OccurredAt: completed}
	return s.commitPathChange(r, test, previous, byVantage, &event)
}

func (s *Server) commitPathChange(r *http.Request, test *store.Test, previous []byte, next map[string]pathChangeState, event *change.Event) error {
	actor := auth.PrincipalFrom(r.Context())
	current := s.resolvePrincipal(r)
	if actor == nil || current == nil || actor.TenantID != test.TenantID || !auth.SamePrincipalAuthority(actor, current) {
		return tenancy.ErrNoTenant
	}
	ctx := tenancy.WithSiloTableLock(r.Context())
	var result *incident.Incident
	var opened bool
	err := s.inTenant(r.WithContext(ctx), func(ctx context.Context, sc tenancy.Scope) error {
		tenant := sc.Tenant.String()
		var locked []byte
		if err := sc.Q.QueryRow(ctx, `SELECT coalesce(path_change_state, 'null'::jsonb)::text FROM tests
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 FOR UPDATE`, tenant, test.ID, test.UpdatedAt).Scan(&locked); err != nil {
			return err
		}
		if !bytes.Equal(previous, locked) {
			return errPathChangeStateMoved
		}
		document, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE tests SET path_change_state=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, test.ID, document); err != nil {
			return err
		}
		if event == nil {
			return nil
		}
		entry, err := (store.ChangeEvents{}).Create(ctx, sc, *event)
		if err != nil {
			return err
		}
		notify, _ := testspec.PathChangeOptions(test.Params)
		fields := map[string]any{"change_id": entry.ID, "vantage": event.Attributes["vantage"], "alerts_enabled": notify}
		if !notify {
			return audit.TenantRecord(ctx, sc, actor.UserID, "path.change.confirmed", test.ID, fields)
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, tenant); err != nil {
			return err
		}
		signal := incident.Signal{TenantID: tenant, Plane: "network", Kind: "path.change", Severity: incident.SeverityWarning,
			Target: "test:" + test.ID + ":" + event.Attributes["vantage_id"], Title: event.Title, Summary: event.Summary,
			OccurredAt: event.OccurredAt, Attributes: map[string]string{"probectl.path.change_id": entry.ID, "probectl.test.id": test.ID}}
		correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, s.cfg.IncidentWindow, s.log,
			incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
		result, err = correlator.Ingest(ctx, signal)
		if err != nil {
			return err
		}
		if result == nil || result.TenantID != tenant {
			return tenancy.ErrNoTenant
		}
		fields["incident_id"] = result.ID
		return audit.TenantRecord(ctx, sc, actor.UserID, "path.change.confirmed", test.ID, fields)
	})
	if err == nil && result != nil && s.pathChangeObserver != nil {
		s.pathChangeObserver(tenancy.WithTenant(ctx, tenancy.ID(test.TenantID)), result, opened)
	}
	return err
}
