// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestMessageCodecOpenSnapshotsAuthenticatedCiphertextPair(t *testing.T) {
	f := newMessageCodecFixture(t)
	original := []byte(`{"question":"authenticated original"}`)
	record := f.seal(t, original)
	replacement := f.seal(t, []byte(`{"question":"same-scope replacement"}`))
	parts := *record.parts
	defer func() { *record.parts = parts }()
	got, err := f.codec.Open(f.context, f.scope, record, func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, requirements []string) error {
		if err := f.authorize(ctx, scope, origin, requirements); err != nil {
			return err
		}
		// Simulate private repository backing storage being reused after header
		// authentication. No public API can mutate these private fields.
		*record.parts = *replacement.parts
		return nil
	})
	defer clear(got)
	if err != nil || string(got) != string(original) {
		t.Fatal("authorization callback replaced the authenticated ciphertext pair", err)
	}
}
