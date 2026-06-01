package control

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/netctl/internal/alert"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/tsdb"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// tsdbQuerier is the read side of the in-memory TSDB the evaluator needs.
type tsdbQuerier interface {
	Query(metric string, match map[string]string) []tsdb.Series
}

// metricSource adapts the TSDB to alert.MetricSource for one tenant: every query
// is constrained to the tenant's series (tenant_id label), so the evaluator can
// never read another tenant's metrics (F50). It returns the latest value per
// distinct label set.
type metricSource struct {
	q      tsdbQuerier
	tenant string
}

func (m metricSource) Current(_ context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	scoped := map[string]string{"tenant_id": m.tenant}
	for k, v := range match {
		scoped[k] = v
	}
	rows := m.q.Query(metric, scoped)

	latest := make(map[string]alert.Sample, len(rows))
	order := make([]string, 0, len(rows))
	for _, s := range rows {
		fp := labelFingerprint(s.Labels)
		if _, seen := latest[fp]; !seen {
			order = append(order, fp)
		}
		latest[fp] = alert.Sample{Labels: s.Labels, Value: s.Value}
	}
	out := make([]alert.Sample, 0, len(order))
	for _, fp := range order {
		out = append(out, latest[fp])
	}
	return out, nil
}

func labelFingerprint(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(';')
	}
	return b.String()
}

// tenantRuleProvider loads a tenant's enabled rules through the RLS choke point.
type tenantRuleProvider struct {
	pool   *pgxpool.Pool
	tenant tenancy.ID
}

func (p tenantRuleProvider) Rules(ctx context.Context) ([]alert.Rule, error) {
	var rules []alert.Rule
	err := tenancy.InTenant(tenancy.WithTenant(ctx, p.tenant), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			rs, e := store.AlertRules{}.ListEnabled(c, sc)
			rules = rs
			return e
		})
	return rules, err
}

// BuildAlertEvaluator wires the alerting evaluator over the shared TSDB and the
// rule store for one tenant. It returns (nil, false) when the TSDB cannot be
// queried in-process (e.g. Prometheus remote-write mode) — alerting then needs a
// query backend (a follow-up), and the caller skips the loop rather than failing.
//
// Single-tenant wiring: a multi-tenant deployment runs one evaluator per tenant
// (a fan-out refinement); here the default tenant is evaluated.
// A non-nil sink forwards every fired/resolved alert (e.g. into the incident
// correlator, S17).
func BuildAlertEvaluator(pool *pgxpool.Pool, writer any, deps alert.ChannelDeps,
	interval time.Duration, tenant tenancy.ID, sink func(context.Context, alert.Alert),
	log *slog.Logger) (*alert.Evaluator, bool) {
	q, ok := writer.(tsdbQuerier)
	if !ok || pool == nil {
		return nil, false
	}
	var opts []alert.EngineOption
	if sink != nil {
		opts = append(opts, alert.WithAlertSink(sink))
	}
	engine := alert.NewEngine(metricSource{q: q, tenant: tenant.String()}, alert.NewNotifier(deps, log), log, opts...)
	provider := tenantRuleProvider{pool: pool, tenant: tenant}
	return alert.NewEvaluator(engine, provider, interval, log), true
}
