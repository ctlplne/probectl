// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/httpbody"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// changeWebhookMaxBody caps an (untrusted) webhook payload at 1 MiB.
const changeWebhookMaxBody = 1 << 20

// handleChangeWebhook ingests a per-provider-signed change webhook (S29). It is
// mounted OUTSIDE the session-authenticated /v1 surface (like /auth/login) and
// authenticates the delivery itself: the {id} selects a configured credential
// (tenant + provider + secret), the provider verifies the signature/token, and a
// verified body is normalized and persisted under the CREDENTIAL's tenant — never
// the (untrusted) payload's. An unsigned or forged delivery is rejected before any
// normalization or RCA exposure, so a forged change event can never reach the RCA
// and one tenant cannot inject another tenant's changes (CLAUDE.md §7 guardrail 12).
func (s *Server) handleChangeWebhook(w http.ResponseWriter, r *http.Request) error {
	provider := r.PathValue("provider")
	id := r.PathValue("id")

	cred, ok := s.cfg.ChangeWebhooks[id]
	if !ok || !strings.EqualFold(cred.Provider, provider) {
		// Unknown id, or the URL provider doesn't match the credential: fail closed
		// without revealing which (no enumeration oracle).
		return apierror.Unauthorized("unknown or unauthorized webhook")
	}
	p, ok := change.ProviderByName(cred.Provider)
	if !ok {
		return apierror.Unauthorized("unknown or unauthorized webhook")
	}

	body, err := httpbody.ReadLimited(r.Body, changeWebhookMaxBody)
	if err != nil {
		if errors.Is(err, httpbody.ErrTooLarge) {
			return apierror.TooLarge("change webhook body exceeds size cap")
		}
		return apierror.BadRequest("cannot read request body")
	}
	if !p.Verify(cred.Secret, body, r.Header) {
		// unsigned / forged / wrong-token → reject before normalization (fail closed).
		return apierror.Unauthorized("invalid webhook signature")
	}

	events, err := p.Normalize(body, r.Header, time.Now().UTC())
	if err != nil {
		return apierror.BadRequest("cannot parse change payload")
	}

	stored := 0
	if len(events) > 0 {
		if s.pool == nil {
			return apierror.Internal("change ingestion requires a database")
		}
		ctx := tenancy.WithTenant(r.Context(), tenancy.ID(cred.TenantID))
		if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			for i := range events {
				events[i].TenantID = cred.TenantID // bind to the verified credential
				if _, e := (store.ChangeEvents{}).Create(ctx, sc, events[i]); e != nil {
					return e
				}
				stored++
			}
			_, e := audit.TenantAppend(ctx, sc, "webhook:"+cred.Provider, "change.ingest", id,
				map[string]any{"events": stored, "provider": cred.Provider})
			return e
		}); err != nil {
			return err
		}
	}
	s.log.Info("change webhook ingested", "provider", cred.Provider, "tenant_id", cred.TenantID, "events", stored)
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": stored, "provider": cred.Provider})
	return nil
}

// handleListChanges returns the caller tenant's change timeline (newest first).
func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request) error {
	var evs []change.Event
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.ChangeEvents{}.List(ctx, sc, 200)
		evs = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": evs})
	return nil
}

// handleIncidentChanges returns the change events correlated to an incident —
// recent changes that share the incident's target/prefix within the correlation
// window, ranked as candidate causes (the "what changed" view, fed to RCA).
func (s *Server) handleIncidentChanges(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	window := s.cfg.ChangeCorrelationWindow
	if window <= 0 {
		window = 24 * time.Hour
	}
	var cands []change.Candidate
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		inc, e := store.Incidents{}.Get(ctx, sc, id)
		if e != nil {
			return e
		}
		evs, e := store.ChangeEvents{}.Since(ctx, sc, inc.StartedAt.Add(-window), 500)
		if e != nil {
			return e
		}
		cands = change.Candidates(evs, inc.Target, inc.Prefix, inc.StartedAt, window)
		return nil
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": cands})
	return nil
}

// changeEventsSource is the ai.EventsSource backed by production event stores:
// the Postgres change timeline plus direct flow summaries when the flow store is
// attached. It opens tenant-scoped (RLS) Postgres reads and passes the engine's
// tenant into the flow store; callers never provide tenant scope.
type changeEventsSource struct {
	pool *pgxpool.Pool
	flow flowstore.Store
}

func (s changeEventsSource) QueryEvents(ctx context.Context, tenant string, sel map[string]string, r ai.TimeRange, limit int) ([]ai.Row, error) {
	var rows []ai.Row
	typ := strings.ToLower(sel["type"])
	if typ == "" || typ == "change" || typ == "bgp" || typ == "routing" {
		if s.pool != nil {
			if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
				start, end := changeEvidenceWindow(r)
				evs, err := (store.ChangeEvents{}).Between(ctx, sc, start, end, limit)
				if err != nil {
					return err
				}
				target, prefix := sel["target"], sel["prefix"]
				for i := range evs {
					ev := evs[i]
					if !changeMatches(ev, target, prefix) || !eventTypeMatches(ev, typ) {
						continue
					}
					plane := eventPlane(ev)
					rows = append(rows, ai.Row{
						"id": ev.ID, "kind": eventKind(ev, plane), "plane": plane, "source": ev.Source,
						"change_kind": string(ev.Kind), "title": ev.Title, "summary": ev.Summary,
						"target": ev.Target, "prefix": ev.Prefix, "actor": ev.Actor, "ref": ev.Ref,
						"occurred_at": ev.OccurredAt,
					})
					if len(rows) >= limit {
						break
					}
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}
	if len(rows) < limit && (typ == "" || typ == "flow") && s.flow != nil {
		flowRows, err := s.queryFlowEvents(ctx, tenant, sel, r, limit-len(rows))
		if err != nil {
			return nil, err
		}
		rows = append(rows, flowRows...)
	}
	return rows, nil
}

func changeEvidenceWindow(r ai.TimeRange) (time.Time, time.Time) {
	end := r.End
	if end.IsZero() {
		end = time.Now().UTC()
	} else {
		end = end.UTC()
	}
	start := r.Start
	if start.IsZero() {
		start = end.Add(-24 * time.Hour)
	} else {
		start = start.UTC()
	}
	return start, end
}

func (s changeEventsSource) queryFlowEvents(ctx context.Context, tenant string, sel map[string]string, r ai.TimeRange, limit int) ([]ai.Row, error) {
	if limit <= 0 {
		return nil, nil
	}
	window := r.End.Sub(r.Start)
	if r.Start.IsZero() || r.End.IsZero() || window <= 0 {
		window = time.Hour
	}
	now := r.End
	if now.IsZero() {
		now = time.Now()
	}
	by := flowstore.BySrc
	switch {
	case sel["dst"] != "" || sel["target"] != "":
		by = flowstore.ByDst
	case sel["asn"] != "":
		by = flowstore.BySrcASN
	}
	tops, err := s.flow.TopTalkers(ctx, flowstore.TopQuery{TenantID: tenant, By: by, Window: window, Limit: limit, Now: now})
	if err != nil {
		return nil, err
	}
	target := sel["target"]
	out := make([]ai.Row, 0, len(tops))
	for i, row := range tops {
		if target != "" && row.Key != target && row.Detail != target {
			continue
		}
		out = append(out, ai.Row{
			"id":      fmt.Sprintf("flow:%s:%d", by, i+1),
			"kind":    "flow.top_talker",
			"plane":   "flow",
			"source":  "flowstore",
			"title":   fmt.Sprintf("flow top talker %s", row.Key),
			"summary": fmt.Sprintf("%d bytes across %d flows", row.Bytes, row.Flows),
			"target":  row.Key,
			"ref":     "flow:" + by + ":" + row.Key,
			"bytes":   row.Bytes,
			"packets": row.Packets,
			"flows":   row.Flows,
			"detail":  row.Detail,
		})
	}
	return out, nil
}

func eventTypeMatches(ev change.Event, typ string) bool {
	switch typ {
	case "", "change":
		return true
	case "bgp", "routing":
		return eventPlane(ev) == "bgp"
	default:
		return false
	}
}

func eventPlane(ev change.Event) string {
	source := strings.ToLower(ev.Source)
	kind := strings.ToLower(string(ev.Kind))
	if source == "bgp" || strings.Contains(kind, "bgp") || strings.Contains(kind, "route") || strings.Contains(kind, "routing") {
		return "bgp"
	}
	return "change"
}

func eventKind(ev change.Event, plane string) string {
	if plane == "bgp" {
		return "bgp." + strings.TrimPrefix(strings.ToLower(string(ev.Kind)), "bgp.")
	}
	return "change"
}

// changeMatches keeps a change as evidence when it concerns the question's subject
// (or when there is no subject — then recent changes are all relevant context).
func changeMatches(ev change.Event, target, prefix string) bool {
	if target == "" && prefix == "" {
		return true
	}
	return change.Relevant(ev, target, prefix)
}
