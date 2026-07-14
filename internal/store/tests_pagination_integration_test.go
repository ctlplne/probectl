// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TestTestsPagination is the SCALE-002 acceptance test: the tests table is paged
// (ListPage bounds a single query; ListAll pages through the full set) and the
// page never exceeds the requested limit. It also asserts cross-tenant isolation
// — a second tenant's tests never appear in the first tenant's pages (CLAUDE.md
// §7.1). Pre-fix, Tests.ListPage/ListAll did not exist and List() loaded the
// whole table unbounded.
func TestTestsPagination(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	mk := func(prefix string, n int) tenancy.ID {
		tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()), prefix)
		if err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		id := tenancy.ID(tn.ID)
		inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
			for i := 0; i < n; i++ {
				in := TestInput{
					Name: fmt.Sprintf("t-%d", i), Type: "icmp",
					Target:          fmt.Sprintf("203.0.113.%d", i%250),
					IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true,
				}
				if _, err := (Tests{}).Create(ctx, sc, in); err != nil {
					return err
				}
			}
			return nil
		})
		return id
	}

	const tenantA, tenantB = 2500, 17
	idA := mk("scale002-a", tenantA)
	idB := mk("scale002-b", tenantB)

	inTenant(ctx, t, pool, idA.String(), func(ctx context.Context, sc tenancy.Scope) error {
		// A single page is bounded by the requested limit.
		page, err := (Tests{}).ListPage(ctx, sc, "", 200)
		if err != nil {
			return err
		}
		if len(page) != 200 {
			t.Fatalf("first page = %d rows, want exactly the limit (200)", len(page))
		}
		// An over-cap limit is clamped, never honored unbounded.
		over, err := (Tests{}).ListPage(ctx, sc, "", 1_000_000)
		if err != nil {
			return err
		}
		if len(over) > maxTestPageSize {
			t.Fatalf("limit 1,000,000 returned %d rows, want <= cap %d", len(over), maxTestPageSize)
		}
		// ListAll pages through and returns the complete tenant set.
		all, err := (Tests{}).ListAll(ctx, sc, 0)
		if err != nil {
			return err
		}
		if len(all) != tenantA {
			t.Fatalf("ListAll = %d, want %d (the full tenant set via bounded pages)", len(all), tenantA)
		}
		return nil
	})

	// Cross-tenant isolation: tenant B sees only its own rows.
	inTenant(ctx, t, pool, idB.String(), func(ctx context.Context, sc tenancy.Scope) error {
		all, err := (Tests{}).ListAll(ctx, sc, 0)
		if err != nil {
			return err
		}
		if len(all) != tenantB {
			t.Fatalf("tenant B ListAll = %d, want %d (no cross-tenant leakage)", len(all), tenantB)
		}
		return nil
	})
}
