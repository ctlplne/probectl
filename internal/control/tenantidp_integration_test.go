// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

func TestTenantIdPAdminAPIIsolationEncryptionAndAudit(t *testing.T) {
	sealer, err := tenantcrypto.NewEnvelopeSealer("tenant-idp-api-test",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)

	h, db := setupAPI(t)
	tenantA := freshTenant(t, db, "idp-api-a")
	tenantB := freshTenant(t, db, "idp-api-b")
	body := map[string]any{
		"issuer": "https://idp-a.example", "client_id": "probectl-a",
		"client_secret": "super-secret-a", "redirect_url": "https://a.example/auth/callback",
		"scopes": []string{"openid", "email"}, "enabled": true,
	}
	put := apiReq(t, h, http.MethodPut, "/v1/identity/settings", tenantA, body)
	if put.Code != http.StatusOK {
		t.Fatalf("tenant A IdP update: %d %s", put.Code, put.Body)
	}
	if strings.Contains(put.Body.String(), "super-secret-a") || strings.Contains(put.Body.String(), "dv1:") {
		t.Fatalf("IdP update response leaked secret material: %s", put.Body)
	}
	if !strings.Contains(put.Body.String(), `"source":"tenant"`) ||
		!strings.Contains(put.Body.String(), `"client_secret_configured":true`) {
		t.Fatalf("IdP update response missing safe metadata: %s", put.Body)
	}

	getA := apiReq(t, h, http.MethodGet, "/v1/identity/settings", tenantA, nil)
	if getA.Code != http.StatusOK || !strings.Contains(getA.Body.String(), "https://idp-a.example") {
		t.Fatalf("tenant A IdP read: %d %s", getA.Code, getA.Body)
	}
	getB := apiReq(t, h, http.MethodGet, "/v1/identity/settings", tenantB, nil)
	if getB.Code != http.StatusOK || strings.Contains(getB.Body.String(), "idp-a") ||
		!strings.Contains(getB.Body.String(), `"source":"none"`) {
		t.Fatalf("tenant B saw tenant A IdP metadata: %d %s", getB.Code, getB.Body)
	}

	var stored string
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT client_secret_sealed FROM tenant_idp WHERE tenant_id=$1`, tenantA).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "super-secret-a" || !tenantcrypto.HasScheme(stored) {
		t.Fatalf("client secret is not envelope-sealed: %q", stored)
	}

	// Omitting client_secret rotates no key and preserves the sealed value.
	body["client_secret"] = ""
	body["issuer"] = "https://idp-a-new.example"
	if update := apiReq(t, h, http.MethodPut, "/v1/identity/settings", tenantA, body); update.Code != http.StatusOK {
		t.Fatalf("metadata-only IdP update: %d %s", update.Code, update.Body)
	}
	var after string
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT client_secret_sealed FROM tenant_idp WHERE tenant_id=$1`, tenantA).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != stored {
		t.Fatal("blank client_secret did not preserve the existing sealed secret")
	}

	err = tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx,
				`SELECT count(*) FROM audit_events WHERE action='identity.idp_update'`).Scan(&count); err != nil {
				return err
			}
			if count != 2 {
				t.Fatalf("identity.idp_update audit count=%d, want 2", count)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
