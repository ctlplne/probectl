// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/httpbody"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const itsmWebhookMaxBody = 1 << 20

// pgLinkStore implements notify.LinkStore over store.IncidentIntegrations,
// scoping every operation to the tenant through the RLS choke point. A link is
// never visible across tenants.
type pgLinkStore struct{ pool *pgxpool.Pool }

func (p pgLinkStore) Get(ctx context.Context, tenant, incidentID, connector string) (*notify.Link, error) {
	var out *notify.Link
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			l, e := (store.IncidentIntegrations{}).Get(c, sc, incidentID, connector)
			out = l
			return e
		})
	return out, err
}

func (p pgLinkStore) FindByRef(ctx context.Context, tenant, connector, ref string) (*notify.Link, error) {
	var out *notify.Link
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			l, e := (store.IncidentIntegrations{}).FindByRef(c, sc, connector, ref)
			out = l
			return e
		})
	return out, err
}

func (p pgLinkStore) Upsert(ctx context.Context, l notify.Link) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(l.TenantID)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			return (store.IncidentIntegrations{}).Upsert(c, sc, l)
		})
}

// BuildDispatcher constructs the on-call/ITSM dispatcher from config. It returns
// (nil, false) unless connectors are configured — OFF by default, since each
// connector is an outbound connection to the operator's tooling. Per-tenant
// routing: a connector only ever fires for its own tenant.
func BuildDispatcher(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) (*notify.Dispatcher, bool) {
	if log == nil {
		log = slog.Default()
	}
	if cfg == nil || pool == nil || len(cfg.NotifyConnectors) == 0 {
		return nil, false
	}
	d := notify.NewDispatcher(pgLinkStore{pool: pool}, log)
	n := 0
	for _, nc := range cfg.NotifyConnectors {
		c, ok := notify.NewConnector(nc.Provider, nc.Endpoint, nc.Secret, nil)
		if !ok {
			log.Warn("notify: unknown connector provider; skipping", "provider", nc.Provider)
			continue
		}
		d.Register(nc.TenantID, c)
		n++
	}
	if n == 0 {
		return nil, false
	}
	return d, true
}

// NotifyObserver returns an incident observer that pages on-call + opens tickets
// when an incident OPENS (S33). A correlated update to an existing incident is not
// re-notified (avoid alert spam). A nil dispatcher is a no-op.
func NotifyObserver(d *notify.Dispatcher, _ *slog.Logger) incident.Observer {
	return func(ctx context.Context, inc *incident.Incident, opened bool) {
		if d == nil || inc == nil || !opened {
			return
		}
		d.Opened(ctx, *inc)
	}
}

// handleITSMWebhook ingests an inbound status-sync webhook from an ITSM/on-call
// system (S33). It authenticates the delivery (HMAC/token over TLS), maps the
// external ref back to the incident (tenant-scoped), resolves the incident on a
// "resolved", then syncs the OTHER connectors — never echoing back to the origin
// (loop protection). It is mounted off /v1 (an ingest surface) and authenticates
// itself, like the change-webhook receiver.
func (s *Server) handleITSMWebhook(w http.ResponseWriter, r *http.Request) error {
	provider := r.PathValue("provider")
	id := r.PathValue("id")

	cred, ok := s.cfg.NotifyInbound[id]
	if !ok || !strings.EqualFold(cred.Provider, provider) {
		// Unknown id, or the URL provider doesn't match: fail closed (no oracle).
		return apierror.Unauthorized("unknown or unauthorized webhook")
	}
	body, err := httpbody.ReadLimited(r.Body, itsmWebhookMaxBody)
	if err != nil {
		if errors.Is(err, httpbody.ErrTooLarge) {
			return apierror.TooLarge("ITSM webhook body exceeds size cap")
		}
		return apierror.BadRequest("cannot read request body")
	}
	if !notify.VerifyInbound(cred.Secret, body, r.Header) {
		// unsigned / forged / wrong-token → reject before any state change.
		return apierror.Unauthorized("invalid webhook signature")
	}
	res, ok := notify.ParseInbound(provider, body)
	if !ok {
		return apierror.BadRequest("cannot parse webhook payload")
	}
	if s.pool == nil {
		return apierror.Internal("itsm sync requires a database")
	}

	var resolved *incident.Incident
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(cred.TenantID))
	if err := tenancy.InTenant(ctx, s.pool, func(c context.Context, sc tenancy.Scope) error {
		link, e := (store.IncidentIntegrations{}).FindByRef(c, sc, provider, res.ExternalRef)
		if e != nil || link == nil {
			return e // unknown external ref → no-op
		}
		if !res.Resolved {
			return nil
		}
		inc, e := (store.Incidents{}).Get(c, sc, link.IncidentID)
		if e != nil {
			return e
		}
		if inc.Status != incident.StatusOpen {
			return nil // already resolved — idempotent
		}
		x, e := (store.Incidents{}).Resolve(c, sc, link.IncidentID)
		if e != nil {
			return e
		}
		resolved = x
		_, e = audit.TenantAppend(c, sc, "webhook:"+provider, "incident.resolve", link.IncidentID,
			map[string]any{"source": provider, "external_ref": res.ExternalRef})
		return e
	}); err != nil {
		return err
	}

	// Sync the resolution to the OTHER connectors (the dispatcher skips the origin
	// — loop protection — and marks the origin's link resolved).
	if resolved != nil && s.dispatcher != nil {
		s.dispatcher.Resolved(r.Context(), *resolved, provider)
	}
	s.log.Info("itsm webhook ingested", "provider", provider, "tenant_id", cred.TenantID, "resolved", resolved != nil)
	writeJSON(w, http.StatusAccepted, map[string]any{"provider": provider, "resolved": resolved != nil})
	return nil
}
