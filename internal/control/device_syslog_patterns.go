// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type deviceSyslogPatternReader interface {
	ListSyslogPatterns(context.Context, string, device.SyslogPatternSelection) (device.SyslogPatternCounts, error)
}

type deviceSyslogPatternPage struct {
	device.SyslogPatternCounts
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

func (s *Server) handleListDeviceSyslogPatterns(w http.ResponseWriter, r *http.Request) error {
	tenant, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	reader, ok := s.deviceOps.(deviceSyslogPatternReader)
	if !ok {
		return apierror.Unavailable("device syslog pattern storage is unavailable")
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if budget.Validate() != nil {
		return apierror.Unavailable("device syslog pattern admission is unavailable")
	}
	selection, err := syslogPatternSelection(r, budget.MemoryBytes/256)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(tenant)), budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, tenant)
		if err != nil {
			return tagQueryAdmissionError(err)
		}
		defer release()
	}
	result, err := reader.ListSyslogPatterns(ctx, tenant, selection)
	if errors.Is(err, device.ErrSyslogPatternBudget) {
		return apierror.TooLarge("the complete device syslog pattern population exceeds configured query memory")
	}
	if err != nil {
		return err
	}
	page := deviceSyslogPatternPage{SyslogPatternCounts: result, From: selection.From, To: selection.To}
	body, err := json.Marshal(page)
	if err != nil {
		return apierror.Unavailable("device syslog pattern output is unavailable")
	}
	if int64(len(body)) > budget.ResponseBytes || int64(len(body)) > budget.MemoryBytes/4 {
		return apierror.TooLarge("the complete device syslog pattern page exceeds configured response admission")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}

func syslogPatternSelection(r *http.Request, maxInputRows int64) (device.SyslogPatternSelection, error) {
	values := r.URL.Query()
	from, fromErr := time.Parse(time.RFC3339Nano, values.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, values.Get("to"))
	if fromErr != nil || toErr != nil || !from.Before(to) {
		return device.SyslogPatternSelection{}, apierror.BadRequest("from and to must delimit an ordered UTC observation range")
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return device.SyslogPatternSelection{}, err
	}
	return device.SyslogPatternSelection{Device: strings.TrimSpace(values.Get("device")), From: from.UTC(), To: to.UTC(),
		Limit: limit, MaxInputRows: maxInputRows}, nil
}
