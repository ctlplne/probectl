// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"errors"
	"testing"
)

func TestPathHealthOriginatingCredentialRequiresActualTransportGuard(t *testing.T) {
	if err := CheckOriginatingCredential(t.Context()); !errors.Is(err, ErrForbidden) {
		t.Fatal("principal-only source dispatch bypassed the transport credential", err)
	}
	if err := CheckOriginatingCredential(withPublicationGuard(t.Context(), nil)); !errors.Is(err, ErrForbidden) {
		t.Fatal("nil originating credential guard did not fail closed", err)
	}
	withdrawn := errors.New("exact bearer revoked")
	called := 0
	ctx := withPublicationGuard(t.Context(), func(context.Context) error { called++; return withdrawn })
	if err := CheckOriginatingCredential(ctx); !errors.Is(err, withdrawn) || called != 1 {
		t.Fatal("originating credential refusal was ignored", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := CheckOriginatingCredential(ctx); !errors.Is(err, context.Canceled) || called != 1 {
		t.Fatal("canceled credential check dispatched", err)
	}
}
