// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type dashboardReportStager func(context.Context, string, reporting.Document) (*reporting.BodyStage, string, error)
type staticReportProfile struct {
	budget  flowstore.ExplorerBudget
	output  reporting.OutputPolicy
	timeout time.Duration
}
type staticReportProfileKey struct{}

func (s *Server) staticReportOperation() (staticReportProfile, error) {
	profile := staticReportProfile{budget: flowstore.DefaultExplorerBudget(), output: reporting.DefaultOutputPolicy(), timeout: time.Minute}
	profile.budget.MemoryBytes = 1 << 30
	if s != nil {
		profile.output = s.reportOutputPolicy()
		if s.cfg != nil {
			if s.cfg.ReportRenderMemoryBytes != 0 {
				profile.budget.MemoryBytes = int64(s.cfg.ReportRenderMemoryBytes)
			}
			if s.cfg.ReportOperationTimeout != 0 {
				profile.timeout = s.cfg.ReportOperationTimeout
			}
		}
	}
	if err := profile.budget.Validate(); err != nil {
		return profile, err
	}
	if err := profile.output.Validate(); err != nil {
		return profile, err
	}
	if profile.timeout <= 0 {
		return profile, reporting.ErrBodyStageLimit
	}
	return profile, nil
}

func staticReportOperation(ctx context.Context) (staticReportProfile, error) {
	if profile, ok := ctx.Value(staticReportProfileKey{}).(staticReportProfile); ok {
		if err := profile.budget.Validate(); err != nil {
			return profile, err
		}
		if err := profile.output.Validate(); err != nil {
			return profile, err
		}
		if profile.timeout <= 0 {
			return profile, reporting.ErrBodyStageLimit
		}
		return profile, nil
	}
	return (*Server)(nil).staticReportOperation()
}

func (p staticReportProfile) context(ctx context.Context) (context.Context, context.CancelFunc) {
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	return context.WithValue(bounded, staticReportProfileKey{}, p), cancel
}

// A static document has no live capture reserve. Its stage and renderer each
// receive half of the same finite operation allowance, without preallocation.
func stageStaticDashboardReport(ctx context.Context, format string, doc reporting.Document) (*reporting.BodyStage, string, error) {
	profile, err := staticReportOperation(ctx)
	if err != nil {
		return nil, "", err
	}
	limits, err := reportBodyStageLimits(profile.output, profile.budget)
	if err != nil {
		return nil, "", err
	}
	media := "application/pdf"
	if format == "csv" {
		media = "text/csv"
	} else if format != "pdf" {
		return nil, "", apierror.Validation("report format must be csv or pdf")
	}
	stage, _, err := reporting.StageBody(ctx, doc.TenantScope, limits, func(target io.Writer) error {
		if format == "csv" {
			render := reporting.DefaultCSVLimits()
			render.TableRows = profile.output.CSVRows * 2
			render.Bytes, render.MemoryBytes = limits.Bytes, profile.budget.MemoryBytes/2
			_, err := reporting.WriteCSV(ctx, target, doc, render)
			return err
		}
		render := reporting.DefaultPDFLimits()
		render.TableRows = profile.output.PDFRows * 2
		render.Bytes, render.MemoryBytes = limits.Bytes, profile.budget.MemoryBytes/2
		_, err := reporting.WritePDF(ctx, target, doc, render)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return stage, media, nil
}

func stageLegacyDashboardReport(ctx context.Context, format string, doc reporting.Document, render dashboardReportRenderer) (*reporting.BodyStage, string, error) {
	profile, err := staticReportOperation(ctx)
	if err != nil {
		return nil, "", err
	}
	limits, err := reportBodyStageLimits(profile.output, profile.budget)
	if err != nil {
		return nil, "", err
	}
	content, media, err := render(ctx, format, doc)
	if err != nil {
		return nil, "", err
	}
	// Legacy callbacks may retain their returned slice; StageBody owns its copies.
	stage, _, err := reporting.StageBody(ctx, doc.TenantScope, limits, func(target io.Writer) error { _, err := target.Write(content); return err })
	if err != nil {
		return nil, "", err
	}
	return stage, media, nil
}

func inlineDashboardStage(ctx context.Context, stage *reporting.BodyStage) ([]byte, error) {
	receipt, err := stage.Receipt(ctx)
	if err != nil {
		return nil, err
	}
	if receipt.Bytes > maxInlineReportBytes {
		return nil, nil
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxInlineReportBytes+1))
	closed := reader.Close()
	if err != nil {
		return nil, err
	}
	if closed != nil {
		return nil, closed
	}
	if int64(len(content)) != receipt.Bytes {
		clear(content)
		return nil, reporting.ErrBodyStageLimit
	}
	if err := ctx.Err(); err != nil {
		clear(content)
		return nil, err
	}
	return content, nil
}

func staticReportMetadata(metadata *store.ReportArtifactMetadata) bool {
	return metadata != nil && len(metadata.SourceCapture) == 0 && (metadata.BodyStorage == "inline" || metadata.BodyStorage == "document-chunks")
}
