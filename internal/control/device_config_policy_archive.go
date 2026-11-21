// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type deviceConfigArchiveCommitter interface {
	ArchiveConfigWithCommit(context.Context, device.ConfigVersion,
		func(context.Context, tenancy.Scope, device.ConfigVersion) error) (device.ConfigVersion, error)
}

func (s *Server) archiveConfigWithPolicy(r *http.Request, writer deviceConfigArchiveCommitter, input device.ConfigVersion) (device.ConfigVersion, error) {
	actor := auth.PrincipalFrom(r.Context())
	return writer.ArchiveConfigWithCommit(r.Context(), input, func(ctx context.Context, sc tenancy.Scope, archive device.ConfigVersion) error {
		if archive.Binding == nil {
			return device.ErrConfigBinding
		}
		if err := s.authorizeDeviceConfigPolicyInScope(ctx, sc, actor, *archive.Binding, permMetricsWrite); err != nil {
			return err
		}
		policy, err := device.LatestConfigPolicy(ctx, sc, *archive.Binding)
		if err != nil {
			return err
		}
		evaluation, err := device.PersistConfigPolicyEvaluation(ctx, sc, archive, policy)
		if err != nil {
			return err
		}
		if err := s.publishConfigPolicyViolation(ctx, sc, archive, evaluation); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "device.config_archive", archive.Device, map[string]any{
			"config_id": archive.ID, "version": archive.Version, "drifted": archive.Drifted, "policy_version": policy.Version,
		})
	})
}

func (s *Server) publishConfigPolicyViolation(ctx context.Context, sc tenancy.Scope, archive device.ConfigVersion,
	evaluation *device.ConfigPolicyEvaluation) error {
	if evaluation == nil {
		return nil
	}
	count := 0
	for _, verdict := range evaluation.Verdicts {
		if verdict.State == "violation" {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return err
	}
	binding := archive.Binding
	signal := incident.Signal{
		TenantID: sc.Tenant.String(), Plane: "device", Kind: "device.config_policy_violation", Severity: incident.SeverityWarning,
		Title: "Device configuration policy violation", Target: "device-policy:" + binding.ContextID + "/" + binding.DeviceEntityID,
		Summary: "One or more rules rejected the captured configuration", OccurredAt: archive.ObservedAt,
		Attributes: map[string]string{"config_archive_id": archive.ID, "policy_version": evaluation.PolicyVersion,
			"violated_rules": strconv.Itoa(count)},
	}
	correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, s.cfg.IncidentWindow, s.log)
	_, err := correlator.Ingest(ctx, signal)
	return err
}

func (s *Server) handleGetDeviceConfigPolicyEvaluation(w http.ResponseWriter, r *http.Request) error {
	archive, result, err := s.readDeviceConfigPolicyEvaluation(r)
	if err != nil {
		return err
	}
	switch r.URL.Query().Get("format") {
	case "", "json":
		writeJSON(w, http.StatusOK, map[string]any{"archive_id": archive.ID, "observed_at": archive.ObservedAt, "evaluation": result})
		return nil
	case "csv":
		if result == nil {
			return apierror.NotFound("this archive has no configuration policy evaluation")
		}
		body, err := configPolicyCSV(r.Context(), result)
		if err != nil {
			return apierror.Unavailable("the complete configuration policy export is unavailable")
		}
		// Revalidate authority after preparing the complete artifact.
		if err := s.authorizeConfigArchiveBinding(r, archive.Binding, ai.PermMetricsRead); err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="probectl-config-policy-`+archive.ID+`.csv"`)
		w.Header().Set("Cache-Control", "no-store")
		_, err = w.Write(body)
		return err
	default:
		return apierror.BadRequest("format must be json or csv")
	}
}

func configPolicyCSV(ctx context.Context, result *device.ConfigPolicyEvaluation) ([]byte, error) {
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	header := []string{"archive_id", "archive_sha256", "policy_version", "evaluated_at", "rule_id", "state", "total_matches", "line_number", "redacted_line"}
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	evaluated := result.EvaluatedAt.UTC().Format(time.RFC3339Nano)
	for _, verdict := range result.Verdicts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := []string{verdict.ArchiveID, verdict.ArchiveSHA256, result.PolicyVersion, evaluated, verdict.RuleID,
			verdict.State, strconv.Itoa(verdict.Matches), "", ""}
		if len(verdict.OffendingLines) == 0 {
			if err := writer.Write(row); err != nil {
				return nil, err
			}
			continue
		}
		for _, witness := range verdict.OffendingLines {
			row[7], row[8] = strconv.Itoa(witness.Number), reporting.CSVText(witness.Text)
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	return body.Bytes(), writer.Error()
}
