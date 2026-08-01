// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantcrypto

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

type keyManagerDelegateSpy struct {
	statusCalls []string
	rotateCalls []string
}

func (s *keyManagerDelegateSpy) KeyStatus(_ context.Context, tenantID string) ([]KeyInfo, error) {
	s.statusCalls = append(s.statusCalls, tenantID)
	return []KeyInfo{{Version: 1, Mode: "managed", State: "active"}}, nil
}

func (s *keyManagerDelegateSpy) RotateKey(_ context.Context, tenantID, _, mode, _ string) (KeyInfo, error) {
	s.rotateCalls = append(s.rotateCalls, tenantID)
	return KeyInfo{Version: len(s.rotateCalls) + 1, Mode: mode, State: "active"}, nil
}

func TestLicenseReadOnlyKeyMutationGateClockAdvancedDelegateSpy(t *testing.T) {
	readOnlyAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	now := readOnlyAt.Add(-time.Second)
	spy := &keyManagerDelegateSpy{}
	manager := GateKeyManagerWrites(spy, license.WriteCapability(func() bool {
		return now.Before(readOnlyAt)
	}))
	ctx := context.Background()
	tenants := []string{"tenant-a", "tenant-b"}

	activeRotations := []struct {
		tenantID string
		mode     string
		byokRef  string
	}{
		{tenantID: tenants[0], mode: "managed"},
		{tenantID: tenants[1], mode: "byok", byokRef: "vault:kv/tenant-b#key"},
	}
	for _, rotation := range activeRotations {
		if _, err := manager.RotateKey(ctx, rotation.tenantID, "user:admin@example.test", rotation.mode, rotation.byokRef); err != nil {
			t.Fatalf("active %s rotate for %s: %v", rotation.mode, rotation.tenantID, err)
		}
	}
	if len(spy.rotateCalls) != len(tenants) {
		t.Fatalf("active rotations reaching delegate = %v, want %v", spy.rotateCalls, tenants)
	}

	// The already-installed gate observes the clock transition. Status remains
	// readable for both tenants, while no post-transition rotation reaches the
	// delegate.
	now = readOnlyAt
	for _, tenantID := range tenants {
		status, err := manager.KeyStatus(ctx, tenantID)
		if err != nil || len(status) != 1 {
			t.Fatalf("read-only status for %s = %+v, %v", tenantID, status, err)
		}
		for _, rotation := range []struct {
			mode    string
			byokRef string
		}{
			{mode: "managed"},
			{mode: "byok", byokRef: "vault:kv/" + tenantID + "#key"},
		} {
			if _, err := manager.RotateKey(ctx, tenantID, "user:admin@example.test", rotation.mode, rotation.byokRef); !errors.Is(err, license.ErrReadOnly) {
				t.Fatalf("read-only %s rotate for %s = %v, want ErrReadOnly", rotation.mode, tenantID, err)
			}
		}
	}
	if len(spy.rotateCalls) != len(tenants) {
		t.Fatalf("read-only rotations reached delegate: %v", spy.rotateCalls)
	}
	if len(spy.statusCalls) != len(tenants) {
		t.Fatalf("read-only status calls did not reach delegate: %v", spy.statusCalls)
	}
}
