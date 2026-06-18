// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestRolloutsTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tnA, err := NewTenants(pool).Create(ctx, fmt.Sprintf("rollout-a-%d", time.Now().UnixNano()), "Rollout A")
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	tnB, err := NewTenants(pool).Create(ctx, fmt.Sprintf("rollout-b-%d", time.Now().UnixNano()), "Rollout B")
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}

	id := "rollout-rls"
	pending := []byte(`{"Target":{"Version":"v0.2.0","Digest":"sha256:abc","Method":"cosign verify","VerifiedBy":"operator"},"Waves":[{"Cohort":"canary","AgentIDs":["agent-a"],"Status":"pending"}],"VerifyWindow":60000000000,"HeartbeatSLO":60000000000}`)
	applying := []byte(`{"Target":{"Version":"v0.2.0","Digest":"sha256:abc","Method":"cosign verify","VerifiedBy":"operator"},"Waves":[{"Cohort":"canary","AgentIDs":["agent-a"],"Status":"applying"}],"VerifyWindow":60000000000,"HeartbeatSLO":60000000000}`)

	inTenant(ctx, t, pool, tnA.ID, func(ctx context.Context, sc tenancy.Scope) error {
		rec, err := (Rollouts{}).Create(ctx, sc, id, pending)
		if err != nil {
			t.Fatalf("create rollout: %v", err)
		}
		if _, err := (Rollouts{}).Update(ctx, sc, id, rec.Revision, applying); err != nil {
			t.Fatalf("update rollout: %v", err)
		}
		if err := (Rollouts{}).AppendEvent(ctx, sc, id, "rollout.advance", applying); err != nil {
			t.Fatalf("append event: %v", err)
		}
		return nil
	})

	inTenant(ctx, t, pool, tnA.ID, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (Rollouts{}).Get(ctx, sc, id)
		if err != nil {
			t.Fatalf("get tenant A rollout: %v", err)
		}
		if string(got.Plan) != string(applying) {
			t.Fatalf("tenant A plan = %s, want %s", got.Plan, applying)
		}
		return nil
	})

	inTenant(ctx, t, pool, tnB.ID, func(ctx context.Context, sc tenancy.Scope) error {
		items, err := (Rollouts{}).List(ctx, sc)
		if err != nil {
			t.Fatalf("list tenant B rollouts: %v", err)
		}
		if len(items) != 0 {
			t.Fatalf("tenant B saw tenant A rollouts: %+v", items)
		}
		_, err = (Rollouts{}).Get(ctx, sc, id)
		if err == nil {
			t.Fatal("tenant B read tenant A rollout by id")
		}
		if e, ok := apierror.As(err); !ok || e.Kind != apierror.KindNotFound {
			t.Fatalf("tenant B get error = %v, want NotFound", err)
		}
		return nil
	})
}
