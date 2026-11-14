// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestChangeTimelinePagesKeepCompleteMixedPopulationAndTenantBoundary(t *testing.T) {
	f := newRoleInputsFixture(t)
	from := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	const stored, configs = 5001, 1002
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO change_events(tenant_id,source,kind,title,occurred_at)
 SELECT $1,'generic','deploy','shared-label-'||n,$2::timestamptz+(n%7)*interval '1 second' FROM generate_series(1,$3) n`, tenant, from, stored); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash,previous_hash,drifted,observed_at,archived_at)
 SELECT $1,'shared-device',n,'secret source content never projected',lpad(to_hex(n),64,'0'),CASE WHEN n>1 THEN lpad(to_hex(n-1),64,'0') ELSE '' END,n>1,
 $2::timestamptz+(n%7)*interval '1 second',$2 FROM generate_series(1,$3) n`, tenant, from, configs)
			return err
		})
	}
	for lane, tenant := range f.tenants {
		seen := map[string]bool{}
		var before time.Time
		beforeID := ""
		configCount := 0
		for pageNumber := 0; ; pageNumber++ {
			var page ChangeTimelinePage
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				page, err = (ChangeEvents{}).TimelinePageInScope(ctx, sc, from, to, before, beforeID, 137, 4<<20)
				return err
			})
			if len(page.Events) == 0 {
				t.Fatal("nonterminal continuation lost mixed history", lane, pageNumber)
			}
			for _, event := range page.Events {
				if event.TenantID != tenant || seen[event.ID] || strings.Contains(event.Summary, "secret source") {
					t.Fatal("page repeated, borrowed or exposed source content", event.ID)
				}
				if !before.IsZero() && (event.OccurredAt.After(before) || (event.OccurredAt.Equal(before) && event.ID <= beforeID)) {
					t.Fatal("timeline continuation reordered equal timestamps")
				}
				seen[event.ID] = true
				if event.Config != nil {
					configCount++
					if event.Config.PreviousVersion != event.Config.CurrentVersion-1 || event.Config.PreviousID == "" {
						t.Fatal("paged config lost predecessor")
					}
				}
				before, beforeID = event.OccurredAt, event.ID
			}
			if !page.More {
				break
			}
			if pageNumber > stored+configs {
				t.Fatal("cursor never exhausted finite fixture")
			}
		}
		if len(seen) != stored+configs-1 || configCount != configs-1 {
			t.Fatal("page size became a population ceiling", len(seen), configCount)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			foreign := tenancy.WithTenant(ctx, tenancy.ID(f.tenants[1-lane]))
			if page, err := (ChangeEvents{}).TimelinePageInScope(foreign, sc, from, to, time.Time{}, "", 137, 4<<20); !errors.Is(err, entity.ErrScopeMismatch) || len(page.Events) != 0 {
				return fmt.Errorf("foreign context reused page scope: %v", err)
			}
			if page, err := (ChangeEvents{}).TimelinePageInScope(ctx, sc, from, to, time.Time{}, "", 137, 4096); !errors.Is(err, ErrClientReportBudget) || len(page.Events) != 0 {
				return fmt.Errorf("under-admitted page returned a prefix: %v", err)
			}
			return nil
		})
	}
}
