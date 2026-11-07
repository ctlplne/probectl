// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This is transport paging, not a row-reach limit: every record remains
// reachable. A page ends only between complete cells/records so masking cannot
// be bypassed with arbitrary byte offsets through a credential or UTF8 value.
func (b nativeMCPFlowBackend) FlowCSV(ctx context.Context, p *auth.Principal, input mcp.NativeFlowCSVInput) (mcp.NativeFlowCSVResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowCSVResult{}, err
	}
	if input.RecordOffset < 0 || input.PageSize < 0 || input.PageSize > flow.MaxPlanPageRows {
		return mcp.NativeFlowCSVResult{}, apierror.Validation("invalid flow CSV record page")
	}
	if input.PageSize == 0 {
		input.PageSize = flow.MaxPlanPageRows
	}
	var result mcp.NativeFlowCSVResult
	prepared, err := b.server.prepareFlowCSVContext(ctx, p, input.SnapshotID, func(ctx context.Context, sc tenancy.Scope, target string, data map[string]any) error {
		data["surface"] = "mcp"
		actor := p.Email
		if actor == "" {
			actor = p.UserID
		}
		_, err := audit.TenantAppend(ctx, sc, actor, "flow.snapshot.csv_export", target, data)
		return err
	}, func(prepared *preparedFlowCSV) error {
		var err error
		result, err = nativeFlowCSVRecordsWithBudget(ctx, prepared, input, b.server.flowRenderBudget, flowstore.ExplorerOperationBudget(ctx, b.server.flowStore).MemoryBytes/8)
		return err
	})
	if err != nil {
		return mcp.NativeFlowCSVResult{}, err
	}
	defer prepared.close()
	if err := ctx.Err(); err != nil {
		return mcp.NativeFlowCSVResult{}, err
	}
	return result, nil
}

// Called while the existing read lease still holds. Walk revalidates retention
// and generation after this bounded projection and before returning success.
func nativeFlowCSVRecords(ctx context.Context, prepared *preparedFlowCSV, input mcp.NativeFlowCSVInput) (mcp.NativeFlowCSVResult, error) {
	return nativeFlowCSVRecordsWithBudget(ctx, prepared, input, mcp.DefaultNativeFlowRenderBudget())
}

func nativeFlowCSVRecordsWithBudget(ctx context.Context, prepared *preparedFlowCSV, input mcp.NativeFlowCSVInput, budget mcp.NativeFlowRenderBudget, memoryLimits ...int64) (mcp.NativeFlowCSVResult, error) {
	if budget.Validate() != nil {
		return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrBudget
	}
	out := mcp.NativeFlowCSVResult{SnapshotID: prepared.header.SnapshotID, ExpiresAt: prepared.header.ExpiresAt, RecordOffset: input.RecordOffset, Records: [][]string{}, SelectedGroups: prepared.header.SelectedRows, SourceBytes: prepared.size, SourceSHA256: prepared.digest}
	reader := csv.NewReader(&nativeCSVCRLFReader{source: bufio.NewReader(flowCSVReader{ctx, prepared.file})})
	var err error
	out.Columns, err = reader.Read()
	if err != nil {
		return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrIntegrity
	}
	used, pageDone := 0, false
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrIntegrity
		}
		index := out.TotalRecords
		out.TotalRecords++
		if index < input.RecordOffset || pageDone {
			continue
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrIntegrity
		}
		if len(encoded) > budget.CSVPageBytes {
			return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrBudget
		}
		if len(out.Records) >= input.PageSize || len(encoded) > budget.CSVPageBytes-used {
			pageDone = true
			continue
		}
		used += len(encoded)
		out.Records = append(out.Records, record)
	}
	if input.RecordOffset > out.TotalRecords {
		return mcp.NativeFlowCSVResult{}, apierror.Validation("flow CSV record offset is beyond the complete export")
	}
	if next := input.RecordOffset + len(out.Records); next < out.TotalRecords {
		out.NextRecord = &next
	}
	remaining := flowstore.DefaultExplorerBudget().MemoryBytes / 8
	if len(memoryLimits) > 1 {
		return mcp.NativeFlowCSVResult{}, flowsnapshot.ErrBudget
	}
	if len(memoryLimits) == 1 {
		remaining = memoryLimits[0]
	}
	if err := projectNativeCSVRoutingPaths(ctx, &out, remaining); err != nil {
		return mcp.NativeFlowCSVResult{}, err
	}
	return out, nil
}

// nativeCSVCRLFReader only reads prepared LF-framed exports from our CSV
// writer. CRLF is therefore cell data. encoding/csv removes one CR before LF;
// duplicate it while streaming so the standard parser returns the exact cell.
// Source bytes/digest remain bound to the untouched original file.
type nativeCSVCRLFReader struct {
	source     *bufio.Reader
	previousCR bool
	pendingLF  bool
}

func (r *nativeCSVCRLFReader) Read(body []byte) (int, error) {
	n := 0
	for n < len(body) {
		if r.pendingLF {
			body[n] = '\n'
			n++
			r.pendingLF = false
			continue
		}
		value, err := r.source.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if value == '\n' && r.previousCR {
			body[n] = '\r'
			n++
			r.pendingLF = true
			r.previousCR = false
			continue
		}
		body[n] = value
		n++
		r.previousCR = value == '\r'
	}
	return n, nil
}
