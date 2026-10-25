// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// lockRecordingFlows records whether each call's context asks for the silo
// table locks: the same context reaches every transaction of the operation.
type lockRecordingFlows struct {
	*flowstore.Memory
	locked map[string]bool
}

func (f *lockRecordingFlows) ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error) {
	f.locked["export"] = tenancy.SiloTableLockContext(ctx)
	return f.Memory.ExportTenant(ctx, tenantID, w)
}

func (f *lockRecordingFlows) DeleteTenant(ctx context.Context, tenantID string) (int64, error) {
	f.locked["erase"] = tenancy.SiloTableLockContext(ctx)
	return f.Memory.DeleteTenant(ctx, tenantID)
}

// D-73 (DPR-401): export and erasure run under WithSiloTableLock, so their
// siloed transactions hold ACCESS SHARE on the silo's tables (proven on real
// Postgres in ee/silo TestDropDuringALongSiloTransactionCannotReachPublic).
func TestExportAndEraseAskForSiloTableLocks(t *testing.T) {
	flows := &lockRecordingFlows{Memory: flowstore.NewMemory(), locked: map[string]bool{}}
	e := New(nil, flows, nil, nil, nil, "", nil)
	var buf bytes.Buffer
	if _, err := e.Export(context.Background(), "t-lock", &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Erase(context.Background(), "t-lock", "t-lock", "operator"); err != nil {
		t.Fatal(err)
	}
	if !flows.locked["export"] || !flows.locked["erase"] {
		t.Fatalf("silo table locks requested = %v, want both export and erasure", flows.locked)
	}
}
