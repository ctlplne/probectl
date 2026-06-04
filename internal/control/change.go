package control

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/store"
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

	body, err := io.ReadAll(io.LimitReader(r.Body, changeWebhookMaxBody))
	if err != nil {
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

// changeEventsSource is the ai.EventsSource backed by the change timeline (S29):
// the RCA's "what changed?" evidence. It opens a tenant-scoped (RLS) transaction
// for the principal's tenant — passed by the engine, never taken from the query —
// so it can never return another tenant's changes.
type changeEventsSource struct{ pool *pgxpool.Pool }

func (s changeEventsSource) QueryEvents(ctx context.Context, tenant string, sel map[string]string, r ai.TimeRange, limit int) ([]ai.Row, error) {
	var rows []ai.Row
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		since := r.Start
		if since.IsZero() {
			since = time.Now().Add(-24 * time.Hour)
		}
		evs, err := (store.ChangeEvents{}).Since(ctx, sc, since, limit)
		if err != nil {
			return err
		}
		target, prefix := sel["target"], sel["prefix"]
		for i := range evs {
			ev := evs[i]
			if !changeMatches(ev, target, prefix) {
				continue
			}
			rows = append(rows, ai.Row{
				"id": ev.ID, "kind": "change", "plane": "change", "source": ev.Source,
				"change_kind": string(ev.Kind), "title": ev.Title, "summary": ev.Summary,
				"target": ev.Target, "prefix": ev.Prefix, "actor": ev.Actor, "ref": ev.Ref,
				"occurred_at": ev.OccurredAt,
			})
			if len(rows) >= limit {
				break
			}
		}
		return nil
	})
	return rows, err
}

// changeMatches keeps a change as evidence when it concerns the question's subject
// (or when there is no subject — then recent changes are all relevant context).
func changeMatches(ev change.Event, target, prefix string) bool {
	if target == "" && prefix == "" {
		return true
	}
	return change.Relevant(ev, target, prefix)
}
