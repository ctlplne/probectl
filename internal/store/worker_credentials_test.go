// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestWorkerCredentialReaderRefusesUnknownScopeBeforeDatabase(t *testing.T) {
	tenant, owner, id := "00000000-0000-0000-0000-000000000101", "00000000-0000-0000-0000-000000000201", "00000000-0000-0000-0000-000000000301"
	other := "00000000-0000-0000-0000-000000000401"
	ref, err := auth.CaptureWorkerCredential(auth.WorkerCredentialSession, tenant, owner, id, crypto.Hash([]byte("owned accepted credential")))
	if err != nil {
		t.Fatal(err)
	}
	reader := WorkerCredentials{} // A database call would fail; no pool exists.
	for _, test := range []struct {
		ctx           context.Context
		tenant, owner string
	}{
		{t.Context(), tenant, owner},
		{tenancy.WithTenant(t.Context(), tenancy.ID(other)), tenant, owner},
		{tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, other},
		{tenancy.WithTenant(t.Context(), tenancy.ID(other)), other, owner},
	} {
		if session, err := reader.RevalidateSession(test.ctx, test.tenant, test.owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) || session != nil {
			t.Fatal("unbound/foreign scope reached a database or obtained metadata", err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if _, err := reader.RevalidateMCP(ctx, tenant, owner, ref); !errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		t.Fatal("session reference selected the MCP table", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := reader.RevalidateSession(ctx, tenant, owner, ref); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read continued to credential lookup", err)
	}
}

func TestWorkerCredentialReaderPreservesUnknownVersusUnavailableWithoutDiagnostics(t *testing.T) {
	for _, test := range []struct{ input, want error }{
		{pgx.ErrNoRows, auth.ErrWorkerCredentialInvalid},
		{auth.ErrWorkerCredentialInvalid, auth.ErrWorkerCredentialInvalid},
		{errors.New("private backend diagnostic"), ErrWorkerCredentialUnavailable},
		{nil, nil},
	} {
		got := workerCredentialReadError(t.Context(), test.input)
		if !errors.Is(got, test.want) || (got != nil && strings.Contains(got.Error(), "private backend")) {
			t.Fatal("credential source error leaked diagnostics or became valid", got)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := workerCredentialReadError(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled publication returned valid credential metadata", err)
	}
	if _, err := NewWorkerCredentials(nil, time.Minute); !errors.Is(err, ErrWorkerCredentialUnavailable) {
		t.Fatal("missing credential pool accepted", err)
	}
	if _, err := NewWorkerCredentials(&pgxpool.Pool{}, -time.Second); !errors.Is(err, ErrWorkerCredentialUnavailable) {
		t.Fatal("negative idle configuration accepted", err)
	}
	configured, err := NewWorkerCredentials(&pgxpool.Pool{}, 0)
	if err != nil || configured.idle != auth.DefaultSessionIdleTimeout {
		t.Fatal("zero config did not preserve the existing session idle default", err)
	}
}
