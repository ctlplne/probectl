// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosApplicationReader func(context.Context, anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error)

func (s *Server) prepareDDoSApplication(ctx context.Context, actor *auth.Principal, settings *ddosAssessmentSettings) error {
	if settings.Input.Application == nil {
		return nil
	}
	if err := s.checkDDoSApplicationAccess(ctx, actor, *settings); err != nil {
		return err
	}
	binding := *settings.Input.Application
	settings.readApplication = func(ctx context.Context, source anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error) {
		if s.otelStore == nil {
			return anomaly.DDoSApplicationWindow{}, false, nil
		}
		tenant, ok := tenancy.FromContext(ctx)
		if !ok || tenant.String() != actor.TenantID || source.TenantID != actor.TenantID {
			return anomaly.DDoSApplicationWindow{}, false, tenancy.ErrNoTenant
		}
		spans, err := otelstore.ReadHTTPObservations(ctx, s.otelStore, tenant.String(), otelstore.SpanQuery{
			Service: binding.Service, Since: source.From, Until: source.To,
			HTTPServer: &otelstore.HTTPServerTarget{Address: source.Target.Addr(), Port: binding.Port},
		})
		if err != nil {
			if ctx.Err() != nil {
				return anomaly.DDoSApplicationWindow{}, false, ctx.Err()
			}
			s.log.Warn("DDoS application context unavailable", "tenant_id", tenant.String())
			return anomaly.DDoSApplicationWindow{}, false, nil
		}
		return projectDDoSApplicationWindow(ctx, source, binding.Service, binding.Port, time.Now().UTC(), spans)
	}
	return nil
}

func (s *Server) checkDDoSApplicationAccess(ctx context.Context, actor *auth.Principal, settings ddosAssessmentSettings) error {
	if settings.Input.Application == nil {
		return nil
	}
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return s.authorizeDDoSApplicationInScope(ctx, sc, actor, settings)
	})
}

func (s *Server) authorizeDDoSApplicationInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, settings ddosAssessmentSettings) error {
	app := settings.Input.Application
	if app == nil {
		return nil
	}
	if actor == nil || actor.TenantID != sc.Tenant.String() {
		return tenancy.ErrNoTenant
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	return s.authorize(ctx, principal, permMetricsRead, auth.RBACGlobal, map[string]string{
		auth.ResourceTenantKey: actor.TenantID, "service_name": app.Service, "protected_prefix": settings.Target.String(),
	})
}

type ddosApplicationRequest struct {
	Trace, Span string
	Started     time.Time
	Duration    time.Duration
	Success     bool
}

func projectDDoSApplicationWindow(ctx context.Context, source anomaly.DDoSObservation, service string, port uint16,
	knownAt time.Time, spans []otelstore.Span) (anomaly.DDoSApplicationWindow, bool, error) {
	var empty anomaly.DDoSApplicationWindow
	width := source.To.Sub(source.From)
	if width <= 0 || knownAt.Before(source.To) {
		return empty, false, nil
	}
	address, portText := source.Target.Addr().String(), strconv.FormatUint(uint64(port), 10)
	requests := make([]ddosApplicationRequest, 0, len(spans))
	latencies := make([]time.Duration, 0, len(spans))
	seen := make(map[[2]string]bool)
	succeeded := 0
	for _, span := range spans {
		if err := ctx.Err(); err != nil {
			return empty, false, err
		}
		if span.TenantID != source.TenantID || span.Service != service {
			return empty, false, tenancy.ErrNoTenant
		}
		if span.Kind != "server" || span.Start.Before(source.From) || !span.Start.Before(source.To) {
			continue
		}
		if span.Attrs["network.local.address"] != address || span.Attrs["network.local.port"] != portText || span.Attrs["network.transport"] != "tcp" {
			continue
		}
		key := [2]string{span.TraceID, span.SpanID}
		code, err := strconv.Atoi(span.Attrs["http.response.status_code"])
		if err != nil || code < 100 || code > 599 || len(key[0]) != 32 || len(key[1]) != 16 || seen[key] ||
			span.Duration <= 0 || span.Duration > width || span.Start.Add(span.Duration).After(knownAt) {
			// Requests are assigned by their start clock. A request that
			// finished after the boundary can count once its completed span
			// is available. Future or malformed evidence leaves it unknown.
			return empty, false, nil
		}
		seen[key] = true
		success := code >= 200 && code < 400 && span.StatusCode != "error"
		if success {
			succeeded++
		}
		requests = append(requests, ddosApplicationRequest{key[0], key[1], span.Start, span.Duration, success})
		latencies = append(latencies, span.Duration)
	}
	if len(requests) < 20 {
		return empty, false, nil
	}
	slices.Sort(latencies)
	slices.SortFunc(requests, func(a, b ddosApplicationRequest) int {
		if a.Trace == b.Trace {
			return strings.Compare(a.Span, b.Span)
		}
		return strings.Compare(a.Trace, b.Trace)
	})
	body, err := json.Marshal(requests)
	if err != nil {
		return empty, false, err
	}
	return anomaly.DDoSApplicationWindow{TenantID: source.TenantID, Target: source.Target, From: source.From, To: source.To,
		Requests: len(requests), Successes: succeeded, P95: latencies[(len(latencies)*95+99)/100-1], Digest: hex.EncodeToString(crypto.Hash(body))}, true, ctx.Err()
}

func qualifyProjectedDDoS(ctx context.Context, reference, current anomaly.DDoSObservation, finding *anomaly.DDoSDetection,
	read ddosApplicationReader, limits anomaly.DDoSThresholds, work int64) (*anomaly.DDoSDetection, *anomaly.DDoSApplicationEvidence, error) {
	if read == nil || finding == nil || finding.Class != anomaly.DDoSVolumetric {
		return finding, nil, ctx.Err()
	}
	before, usable, err := read(ctx, reference)
	if err != nil || !usable {
		return finding, nil, err
	}
	after, usable, err := read(ctx, current)
	if err != nil || !usable {
		return finding, nil, err
	}
	return anomaly.QualifyDDoSApplication(ctx, reference, current, before, after, finding, limits, work)
}
