// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
)

func TestStaticReportProfileCarriesOperatorCapacityAndCallerCancellation(t *testing.T) {
	server := testServer(fakePinger{})
	server.cfg = &config.Config{ReportRenderMemoryBytes: 2 << 30, ReportOperationTimeout: 25 * time.Hour, ReportMaxBytes: 512 << 20}
	profile, err := server.staticReportOperation()
	if err != nil || profile.budget.MemoryBytes != 2<<30 || profile.timeout != 25*time.Hour || profile.output.Bytes != 512<<20 {
		t.Fatal("static report operator profile lost", err)
	}
	parent, cancel := context.WithCancel(t.Context())
	ctx, stop := profile.context(parent)
	defer stop()
	selected, err := staticReportOperation(ctx)
	if err != nil || selected != profile {
		t.Fatal("static stage discarded captured operation profile", err)
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("static operation outlived caller cancellation")
	}
	deadline := time.Now().Add(time.Second)
	bounded, finish := context.WithDeadline(t.Context(), deadline)
	defer finish()
	child, finishChild := profile.context(bounded)
	defer finishChild()
	if actual, ok := child.Deadline(); !ok || !actual.Equal(deadline) {
		t.Fatal("static profile extended the caller deadline")
	}
	for _, cfg := range []*config.Config{{ReportRenderMemoryBytes: -1}, {ReportOperationTimeout: -1}} {
		server.cfg = cfg
		if _, err := server.staticReportOperation(); err == nil {
			t.Fatal("invalid static operation profile admitted")
		}
	}
}
