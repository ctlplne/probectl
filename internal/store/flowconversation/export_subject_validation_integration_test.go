// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestHistoryJournalPostgresSubjectExportValidatesAncestorsBeforeDirectOutput(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	meta := inputMetadata()
	root := f.red
	root.scope.MessageID = "00000000-0000-4000-8000-000000000050"
	root = seedExportMetadata(t, f.journal, root, "BROKEN_PARENT", meta)
	child := f.red
	child.scope.MessageID = "00000000-0000-4000-8000-000000000010" // First SQL page.
	childMeta := meta
	childMeta.Parent = &Revision{MessageID: root.scope.MessageID, Revision: root.scope.Revision}
	child = seedExportMetadata(t, f.journal, child, "DIRECT_MATCH", childMeta)
	var borrowed [][]byte
	seenAncestor := false
	match := func(ctx context.Context, record StoredMessage, body []byte) (bool, error) {
		borrowed = append(borrowed, body)
		if record.Scope().TenantID != f.red.scope.TenantID || record.Kind() != "input" || !record.Metadata().FrozenAt.Equal(meta.FrozenAt) {
			t.Fatal("application classifier did not receive authenticated record metadata")
		}
		if record.Scope().MessageID == root.scope.MessageID {
			seenAncestor = true
			if record.Metadata().Parent != nil || !bytes.Contains(body, []byte("BROKEN_PARENT")) {
				t.Fatal("ancestor metadata/body did not match its exact SQL record")
			}
			return false, ErrMessageIntegrity
		}
		if record.Scope().MessageID != child.scope.MessageID || record.Metadata().Parent == nil || *record.Metadata().Parent != *childMeta.Parent {
			t.Fatal("child metadata did not match its own exact SQL record")
		}
		return true, ctx.Err()
	}
	var out bytes.Buffer
	installed, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, match, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, err := stream(&out)
		return err
	})
	if !installed || !errors.Is(err, ErrMessageIntegrity) || !seenAncestor || out.Len() != 0 || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("direct match emitted before complete ancestor classification/drain", installed, err, seenAncestor, out.Len())
	}
	for _, body := range borrowed {
		if !bytes.Equal(body, make([]byte, len(body))) {
			t.Fatal("failed subject classifier retained borrowed plaintext")
		}
	}
}
