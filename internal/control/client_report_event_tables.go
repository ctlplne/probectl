// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Complete table projection grants no data access. Signed envelopes are
// self-contained base64 cells, so CSV/PDF downloads need no live share URL or
// external attachment service for offline verification of the evidence index.
func projectClientReportEvents(ctx context.Context, capture *clientReportCapture, memory int64) ([]reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || capture.Events == nil || bound.String() != capture.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	if memory <= 0 || int64(len(capture.Events.Incidents))+int64(len(capture.Events.Changes))+int64(len(capture.Verdicts)) > memory/4096 || len(capture.Verdicts) != len(capture.Events.Incidents) {
		return nil, reportProjectionLimit()
	}
	p := &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}
	verdicts := make(map[string]clientReportVerdict, len(capture.Verdicts))
	evidenceRows := make([][]string, 0, len(capture.Verdicts))
	for _, item := range capture.Verdicts {
		if item.IncidentID == "" || verdicts[item.IncidentID].IncidentID != "" || item.Verdict.IncidentID != item.IncidentID || item.PackageID == "" || item.PackageDigest == "" || len(item.SignedPackage) == 0 {
			return nil, entity.ErrInvalidClaim
		}
		// Encoding expands by at most4/3. Reserve both the complete encoded
		// cell and its renderer workspace before allocating it.
		if int64(len(item.SignedPackage)) > p.memory/16 {
			return nil, reportProjectionLimit()
		}
		if err := p.charge(4096 + int64(len(item.SignedPackage))*8); err != nil {
			return nil, err
		}
		row := []string{capture.TenantID, item.IncidentID, item.PackageID, item.PackageDigest, "probectl-evidence/v1", item.From.UTC().Format(time.RFC3339Nano), item.To.UTC().Format(time.RFC3339Nano), item.SourceDigest, base64.StdEncoding.EncodeToString(item.SignedPackage)}
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		evidenceRows = append(evidenceRows, row)
		verdicts[item.IncidentID] = item
	}
	incidentRows := make([][]string, 0, len(capture.Events.Incidents))
	for _, item := range capture.Events.Incidents {
		verdict, found := verdicts[item.ID]
		if item.TenantID != capture.TenantID || !found {
			return nil, entity.ErrScopeMismatch
		}
		hypotheses, err := json.Marshal(verdict.Verdict.Hypotheses)
		if err != nil {
			return nil, err
		}
		resolved := ""
		if item.ResolvedAt != nil {
			resolved = item.ResolvedAt.UTC().Format(time.RFC3339Nano)
		}
		row := []string{capture.TenantID, item.ID, string(item.Status), string(item.Severity), item.Title, item.Target, item.Prefix, item.StartedAt.UTC().Format(time.RFC3339Nano), item.LastSeenAt.UTC().Format(time.RFC3339Nano), resolved, strconv.Itoa(item.SignalCount), capture.Events.IncidentLineage[item.ID], string(verdict.Verdict.Domain), verdict.Verdict.Confidence, verdict.Verdict.Reason, strconv.FormatBool(verdict.Verdict.Preview), string(hypotheses), verdict.SourceDigest, verdict.PackageID, verdict.PackageDigest}
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		incidentRows = append(incidentRows, row)
	}
	changeRows := make([][]string, 0, len(capture.Events.Changes))
	for _, item := range capture.Events.Changes {
		if item.TenantID != capture.TenantID {
			return nil, entity.ErrScopeMismatch
		}
		attributes, err := json.Marshal(item.Attributes)
		if err != nil {
			return nil, err
		}
		config, err := json.Marshal(item.Config)
		if err != nil {
			return nil, err
		}
		row := []string{capture.TenantID, item.ID, item.Source, string(item.Kind), item.Title, item.Summary, item.Target, item.Prefix, item.Actor, item.Ref, item.URL, string(attributes), string(config), item.OccurredAt.UTC().Format(time.RFC3339Nano), item.ReceivedAt.UTC().Format(time.RFC3339Nano)}
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		changeRows = append(changeRows, row)
	}
	incidentColumns := plainClientReportColumns([]string{"tenant_id", "incident_id", "status", "severity", "title", "target", "prefix", "started_at", "last_seen_at", "resolved_at", "signal_count", "membership_digest", "fault_domain", "confidence", "reason", "preview", "all_hypotheses", "source_digest", "evidence_package_id", "evidence_package_sha256"})
	incidentColumns[10].Numeric = true
	changeColumns := plainClientReportColumns([]string{"tenant_id", "change_id", "source", "kind", "title", "summary", "target", "prefix", "actor", "ref", "url", "attributes", "config_predecessors", "occurred_at", "received_at"})
	evidenceColumns := plainClientReportColumns([]string{"tenant_id", "incident_id", "package_id", "package_sha256", "contract", "window_from", "window_to", "source_digest", "signed_package_base64"})
	tables := []reporting.CSVTable{
		sealedClientReportTable(capture.TenantID, "client-incidents", "Incidents and deterministic verdicts", capture.From, capture.To, incidentColumns, incidentRows),
		sealedClientReportTable(capture.TenantID, "client-changes", "Webhook and archived configuration changes", capture.From, capture.To, changeColumns, changeRows),
		sealedClientReportTable(capture.TenantID, "client-evidence", "Offline-verifiable signed verdict evidence", capture.From, capture.To, evidenceColumns, evidenceRows),
	}
	tables[0].Source = "complete overlapping incident headers/canonical membership and original-source verdicts"
	tables[1].Source = "complete half-open change window plus retained config drift with exact same-tenant predecessors"
	tables[2].Source = "existing probectl-evidence/v1 signed envelopes; verify against the configured public key"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return tables, nil
}

func plainClientReportColumns(names []string) []reporting.CSVColumn {
	columns := make([]reporting.CSVColumn, len(names))
	for index, name := range names {
		columns[index] = reporting.CSVColumn{Name: name}
	}
	return columns
}
