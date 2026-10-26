// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package audit

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestV065TenantAuditUpgradeIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tenants := make([]string, 2)
	for i := range tenants {
		tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("v065-upgrade-%d-%d", time.Now().UnixNano(), i), "Upgrade")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tn.ID
		// Independent historical preimage, intentionally not the production helper.
		header := fmt.Sprintf("%s\n1\nold-writer\nupgrade.seed\nfixture\n\n{}", tn.ID)
		hash := hex.EncodeToString(crypto.Hash([]byte(header)))
		_, err = pool.Exec(ctx, `INSERT INTO audit_events(tenant_id,seq,actor,action,target,data,prev_hash,hash,created_at) VALUES($1,1,'old-writer','upgrade.seed','fixture','{}','','`+hash+`',$2)`, tn.ID, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tid := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tid)), pool, func(ctx context.Context, s tenancy.Scope) error {
			if err := TenantVerify(ctx, s); err != nil {
				return err
			}
			if _, err := TenantAppend(ctx, s, "new-writer", "upgrade.append", "fixture", nil); err != nil {
				return err
			}
			if err := TenantVerify(ctx, s); err != nil {
				return err
			}
			var count int
			if err := s.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id <> $1`, tid).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("foreign audit rows visible: %d", count)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A timestamp change remains detectable on a new row even if its canonical
	// marker is removed. It must not affect the other tenant's verified chain.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET created_at=created_at+interval '1 hour',data_canonical=NULL WHERE tenant_id=$1 AND seq=2`, tenants[0]); err != nil {
		t.Fatal(err)
	}
	for i, tid := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tid)), pool, TenantVerify)
		if (err != nil) != (i == 0) {
			t.Fatalf("tenant %d verification: %v", i, err)
		}
	}
}
