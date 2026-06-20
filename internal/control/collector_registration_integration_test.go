// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

func collectorEnrollService(t *testing.T, db *store.DB) *enroll.Service {
	t.Helper()
	ctx := context.Background()
	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sealer, err := tenantcrypto.NewEnvelopeSealer("test", kek)
	if err != nil {
		t.Fatalf("test envelope sealer: %v", err)
	}
	tenantcrypto.SetPrimary(sealer)
	if _, err := enroll.InitCA(ctx, db.Pool()); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init CA: %v", err)
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		t.Fatalf("load enrollment service: %v", err)
	}
	return svc
}

func TestCollectorRegistrationIsTenantScopedAndPublishBound(t *testing.T) {
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenantA := freshTenant(t, db, "collector-a")
	tenantB := freshTenant(t, db, "collector-b")
	agentID := uuid(t)

	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	token, _, err := svc.MintToken(context.Background(), tenantA, agentID, "edge-flow-1", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cross := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantB, map[string]any{
		"token": token, "plane": "flow", "hostname": "edge-flow-1",
	})
	if cross.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant registration = %d %s, want 401", cross.Code, cross.Body)
	}

	ok := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantA, map[string]any{
		"token": token, "plane": "flow", "hostname": "edge-flow-1",
	})
	if ok.Code != http.StatusCreated {
		t.Fatalf("tenant registration = %d %s, want 201", ok.Code, ok.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.TenantID != tenantA || out.AgentID != agentID || out.Plane != "flow" {
		t.Fatalf("registration response = %+v", out)
	}
	if got := out.Config.Env["PROBECTL_FLOW_AGENT_ID"]; got != agentID {
		t.Fatalf("flow env agent id = %q, want %q", got, agentID)
	}

	binding := pipeline.NewRegistryBinding(db.Pool())
	if err := binding.Verify(context.Background(), tenantA, agentID); err != nil {
		t.Fatalf("registered collector must be publish-bound in its tenant: %v", err)
	}
	if err := binding.Verify(context.Background(), tenantB, agentID); err == nil {
		t.Fatal("collector publish binding crossed tenants")
	}

	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		a, err := (store.Agents{}).Get(ctx, sc, agentID)
		if err != nil {
			return err
		}
		got := strings.Join(a.Capabilities, ",")
		if got != "collector,flow" {
			t.Fatalf("capabilities = %q, want collector,flow", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("read registered collector: %v", err)
	}
}
