// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package audit

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
	selfmetrics "github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/objectstore"
)

// AUD-05: a SQL-side rewrite of an ALREADY-EXPORTED provider row, in a cycle
// with NO new events, must be caught as a chain failure — incrementing
// probectl_audit_worm_chain_failures_total and ExportStatus().ChainFailures,
// which /v1/diagnostics renders as the "verification failing" state. Before the
// fix the cycle only re-read the signed object-store segments and the forward
// export watermark, so a rewrite behind the watermark was invisible until the
// next restart (recordSuccess, not a chain failure).
func TestWormCycleDetectsSQLRewriteOfExportedRowWithoutNewEvents(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	reg := selfmetrics.New("test", "aud05")
	worm, err := NewWormExporterPG(pool, objectstore.NewMemory(), priv, pub, testLog())
	if err != nil {
		t.Fatalf("new worm exporter: %v", err)
	}
	worm.WithMetrics(reg)

	var victim int64
	var orig string
	for i := 0; i < 3; i++ {
		ev, err := ProviderAppend(ctx, pool, "operator", "worm.aud05", "p", map[string]any{"i": i})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if i == 0 {
			victim, orig = ev.Seq, ev.Action
		}
	}

	if _, err := worm.ExportOnce(ctx); err != nil {
		t.Fatalf("initial export: %v", err)
	}
	if got := worm.ExportStatus().ChainFailures; got != 0 {
		t.Fatalf("no chain failures expected before tampering, got %d", got)
	}

	// SQL-side rewrite of an already-exported row (seq behind the export
	// watermark). Restored at the end so the shared provider chain stays valid
	// for other integration tests.
	if _, err := pool.Exec(ctx, `UPDATE provider_audit_events SET action = 'hacked' WHERE seq = $1`, victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `UPDATE provider_audit_events SET action = $2 WHERE seq = $1`, victim, orig)
	}()

	// A cycle with NO new events: nothing beyond the export watermark.
	worm.runCycle(ctx)

	if got := reg.Counter("probectl_audit_worm_chain_failures_total", "").Value(); got < 1 {
		t.Errorf("chain-failure metric must increment on a SQL rewrite, got %d", got)
	}
	if got := reg.Counter("probectl_audit_worm_export_failures_total", "").Value(); got != 0 {
		t.Errorf("tampering must NOT be misclassified as an export/disk failure, got %d", got)
	}
	if got := worm.ExportStatus().ChainFailures; got < 1 {
		t.Errorf("ExportStatus().ChainFailures must be >0 (diagnostics 'verification failing'), got %d", got)
	}
}
