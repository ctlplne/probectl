// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var flowCSVDecimal = regexp.MustCompile(`^[0-9]+(?:\.[0-9]{1,18})?$`)

// Untrusted labels and validated exact metrics follow separate paths.
func flowCSVText(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\ufeff' })
	if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") || len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

type flowCSVFormat struct{ groups, metrics []string }

func newFlowCSVFormat(plan flow.QueryPlan) (flowCSVFormat, []string, error) {
	plan, err := flow.NormalizeQueryPlan(plan, time.Now())
	if err != nil {
		return flowCSVFormat{}, nil, flowsnapshot.ErrIntegrity
	}
	format := flowCSVFormat{groups: plan.GroupBy}
	columns := []string{"record_type"}
	for _, name := range plan.GroupBy {
		columns = append(columns, flowCSVText(name))
	}
	for _, metric := range plan.Metrics {
		key := metric.Measure + ":" + metric.Calculation
		format.metrics = append(format.metrics, key)
		columns = append(columns, flowCSVText(key))
	}
	return format, columns, nil
}
func (f flowCSVFormat) row(row flowstore.PlanRow, kind string) ([]string, error) {
	if kind == "detail" && row.Other || kind == "other" && !row.Other {
		return nil, flowsnapshot.ErrIntegrity
	}
	result := make([]string, 1+len(f.groups)+len(f.metrics))
	result[0] = kind
	if kind == "detail" {
		for i, name := range f.groups {
			value, ok := row.Group[name]
			if !ok {
				return nil, flowsnapshot.ErrIntegrity
			}
			result[1+i] = flowCSVText(value)
		}
	}
	for i, key := range f.metrics {
		value, ok := row.Metrics[key]
		if !ok || len(value) > 256 || !flowCSVDecimal.MatchString(value) {
			return nil, flowsnapshot.ErrIntegrity
		}
		result[1+len(f.groups)+i] = value
	}
	return result, nil
}

type flowCSVWriter struct {
	ctx       context.Context
	target    io.Writer
	remaining int64
}

func (w *flowCSVWriter) Write(body []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(body)) > w.remaining {
		return 0, flowsnapshot.ErrBudget
	}
	n, err := w.target.Write(body)
	w.remaining -= int64(n)
	return n, err
}

type flowCSVReader struct {
	ctx    context.Context
	source io.Reader
}

func (r flowCSVReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(body)
}

type preparedFlowCSV struct {
	file   *os.File
	size   int64
	digest string
	header flowsnapshot.Header
}

func (p *preparedFlowCSV) close() {
	if p.file != nil {
		name := p.file.Name()
		_ = p.file.Close()
		_ = os.Remove(name)
	}
}

// Complete preparation, digest and audit run inside the snapshot read lease.
// No successful headers precede final integrity/retention/generation checks.
type flowCSVPreparedAudit func(context.Context, tenancy.Scope, string, map[string]any) error

// HTTP retains its exact request audit metadata; other trusted transports use
// the same preparation service with their own immutable audit metadata.
func (s *Server) prepareFlowCSV(ctx context.Context, r *http.Request, p *auth.Principal, id string) (*preparedFlowCSV, error) {
	return s.prepareFlowCSVContext(ctx, p, id, func(ctx context.Context, sc tenancy.Scope, target string, data map[string]any) error {
		return s.recordAudit(ctx, sc, r, "flow.snapshot.csv_export", target, data)
	}, nil)
}

func (s *Server) prepareFlowCSVContext(ctx context.Context, p *auth.Principal, id string, preparedAudit flowCSVPreparedAudit, onPrepared func(*preparedFlowCSV) error) (_ *preparedFlowCSV, operationErr error) {
	finish := s.beginFlowOperation(ctx, "csv_prepare")
	defer func() { finish(operationErr) }()
	if preparedAudit == nil {
		return nil, apierror.Unavailable("flow CSV audit is unavailable")
	}

	if s.flowSnapshots == nil || s.flowSnapshotSource == nil {
		return nil, apierror.Unavailable("shared flow results are unavailable")
	}
	scope, err := flowSnapshotScope(p)
	if err != nil {
		return nil, err
	}
	prepared := &preparedFlowCSV{}
	success := false
	defer func() {
		if !success {
			prepared.close()
		}
	}()
	var writer *csv.Writer
	var format flowCSVFormat
	var common explorerResult
	var comparison *explorerComparisonResult
	var comparisonFormat flowComparisonCSVFormat
	count := 0
	err = s.flowSnapshots.Walk(ctx, scope, id, s.flowSnapshotAuthorizer(p), func(header flowsnapshot.Header) error {
		var kind struct {
			ContractVersion string `json:"contract_version"`
		}
		if err := json.Unmarshal(header.Data, &kind); err != nil {
			return flowsnapshot.ErrIntegrity
		}
		var columns []string
		var err error
		if kind.ContractVersion != "" {
			metadata, decodeErr := flowComparisonSnapshotMetadata(header.Data)
			if decodeErr != nil {
				return flowsnapshot.ErrIntegrity
			}
			comparison = &metadata
			comparisonFormat, columns, err = newFlowComparisonCSVFormat(*metadata.Current.Flow, flowstore.ExplorerQueryBudget(s.flowStore))
		} else {
			if err := json.Unmarshal(header.Data, &common); err != nil || common.Flow == nil {
				return flowsnapshot.ErrIntegrity
			}
			format, columns, err = newFlowCSVFormat(common.Flow.Query)
		}
		if err != nil {
			return err
		}
		prepared.file, err = os.CreateTemp(s.flowSnapshotSource.tempDir, "probectl-flow-csv-*")
		if err != nil {
			return err
		}
		prepared.header = header
		writer = csv.NewWriter(&flowCSVWriter{ctx: ctx, target: prepared.file, remaining: s.flowSnapshotSource.exportBytes})
		return writer.Write(columns)
	}, func(rows []json.RawMessage) error {
		for _, raw := range rows {
			if comparison != nil {
				row, err := decodeFlowComparisonSnapshotRow(raw)
				if err != nil {
					return err
				}
				if err := comparisonFormat.write(writer, row.Current, row.Previous, "detail"); err != nil {
					return err
				}
				count++
				continue
			}
			var row flowstore.PlanRow
			if err := json.Unmarshal(raw, &row); err != nil {
				return flowsnapshot.ErrIntegrity
			}
			record, err := format.row(row, "detail")
			if err != nil {
				return err
			}
			if err := writer.Write(record); err != nil {
				return err
			}
			count++
		}
		return nil
	}, func() error {
		if count != prepared.header.SelectedRows {
			return flowsnapshot.ErrIntegrity
		}
		if comparison != nil {
			if comparison.Flow.Current.Other != nil || comparison.Flow.Previous.Other != nil {
				if err := comparisonFormat.write(writer, comparison.Flow.Current.Other, comparison.Flow.Previous.Other, "other"); err != nil {
					return err
				}
			}
			now := &flowstore.PlanRow{Metrics: comparison.Flow.Current.Totals}
			before := &flowstore.PlanRow{Metrics: comparison.Flow.Previous.Totals}
			if err := comparisonFormat.write(writer, now, before, "totals"); err != nil {
				return err
			}
		} else {
			if common.Flow.Other != nil {
				record, err := format.row(*common.Flow.Other, "other")
				if err != nil {
					return err
				}
				if err := writer.Write(record); err != nil {
					return err
				}
			}
			total, err := format.row(flowstore.PlanRow{Metrics: common.Flow.Totals}, "totals")
			if err != nil {
				return err
			}
			if err := writer.Write(total); err != nil {
				return err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return err
		}
		if err := prepared.file.Sync(); err != nil {
			return err
		}
		info, err := prepared.file.Stat()
		if err != nil {
			return err
		}
		prepared.size = info.Size()
		if _, err := prepared.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		digest, err := crypto.HashReader(flowCSVReader{ctx, prepared.file})
		if err != nil {
			return err
		}
		prepared.digest = hex.EncodeToString(digest)
		if _, err := prepared.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(scope.TenantID))), s.flowSnapshotSource.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return preparedAudit(ctx, sc, prepared.header.SnapshotID, map[string]any{"selected_rows": count, "bytes": prepared.size, "sha256": prepared.digest, "outcome": "prepared"})
		}); err != nil {
			return err
		}
		if onPrepared != nil {
			return onPrepared(prepared)
		}
		return nil
	})
	if err != nil {
		return nil, flowSnapshotError(err)
	}
	success = true
	return prepared, nil
}

func (s *Server) handleFlowSnapshotCSV(w http.ResponseWriter, r *http.Request) error {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	p := auth.PrincipalFrom(r.Context())
	prepared, err := s.prepareFlowCSV(r.Context(), r, p, r.PathValue("id"))
	if err != nil {
		return err
	}
	defer prepared.close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-flows-`+prepared.header.SnapshotID+`.csv"`)
	w.Header().Set("Content-Length", strconv.FormatInt(prepared.size, 10))
	w.Header().Set("X-Probectl-SHA256", prepared.digest)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, prepared.file); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Warn("flow CSV response interrupted", "tenant_id", p.TenantID, "snapshot_id", prepared.header.SnapshotID)
	}
	// A transport failure is signaled by length/digest, never appended JSON.
	return nil
}
