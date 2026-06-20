// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func setupEnvelopeRewrapDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, testsupport.PostgresDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestEnvelopeRewrapWorkflowRetiresOldDeploymentKey(t *testing.T) {
	db := setupEnvelopeRewrapDB(t)
	ctx := context.Background()
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))

	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	oldSealer, err := tenantcrypto.NewEnvelopeSealer("old-keys002", oldKey)
	if err != nil {
		t.Fatalf("old sealer: %v", err)
	}
	tenantcrypto.SetPrimary(oldSealer)

	if _, err := db.Pool().Exec(ctx, `DELETE FROM agent_ca`); err != nil {
		t.Fatalf("reset agent_ca: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(), `DELETE FROM agent_ca`)
	})
	tenant, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("keys002-%d", time.Now().UnixNano()), "KEYS-002")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	var alertID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{
			TenantID: tenant.ID, Name: "keys002", Enabled: true,
			Metric: "probe.loss", Type: alert.Threshold, Comparison: alert.GT,
			Threshold: 0.5, Severity: alert.SeverityCritical,
			Channels: []alert.ChannelSpec{{Type: "webhook", URL: "https://hooks.example/keys002", Secret: "rotate-me"}},
		})
		if err != nil {
			return err
		}
		alertID = rule.ID
		return nil
	}); err != nil {
		t.Fatalf("create old alert secret: %v", err)
	}
	if _, err := enroll.InitCA(ctx, db.Pool()); err != nil {
		t.Fatalf("init agent ca under old key: %v", err)
	}

	newWithOld, err := tenantcrypto.NewEnvelopeKeyringSealer("new-keys002", newKey, map[string]string{"old-keys002": oldKey})
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	tenantcrypto.SetPrimary(newWithOld)
	receipt, err := collectEnvelopeRewrap(ctx, db, "new-keys002", "old-keys002", true, false)
	if err != nil {
		t.Fatalf("dry-run inventory: %v", err)
	}
	if receipt.Total.Matched < 2 {
		t.Fatalf("dry-run should find alert + agent CA old ciphertext, got %+v", receipt.Total)
	}

	cfg := &config.Config{EnvelopeKeyID: "new-keys002"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--from-key-id=old-keys002"}); err != nil {
		t.Fatalf("execute rewrap: %v", err)
	}

	currentOnly, err := tenantcrypto.NewEnvelopeSealer("new-keys002", newKey)
	if err != nil {
		t.Fatalf("current-only sealer: %v", err)
	}
	tenantcrypto.Reset()
	tenantcrypto.SetPrimary(currentOnly)
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--verify-retired-key-id=old-keys002"}); err != nil {
		t.Fatalf("verify retired key after opener removal: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, alertID)
		if err != nil {
			return err
		}
		if got := rule.Channels[0].Secret; got != "rotate-me" {
			t.Fatalf("alert secret after rewrap = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("read alert after old opener removal: %v", err)
	}
	if _, err := enroll.Load(ctx, db.Pool(), log); err != nil {
		t.Fatalf("load agent ca after old opener removal: %v", err)
	}
	var auditCount int
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM provider_audit_events WHERE action = 'envelope.rewrap'`).Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("execute rewrap must append a provider audit receipt")
	}
}
