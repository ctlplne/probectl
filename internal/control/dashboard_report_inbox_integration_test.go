// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real application-role Postgres, persisted bearer identities, HTTPS API/CLI
// implementation and native TLS MCP. Metadata bodies are synthetic storage
// fixtures, not real sender or production SSO/release-image receipts.
func TestReportInboxPagesKeepCompleteTenantHistoryAndHiddenSourcesPrivate(t *testing.T) {
	core, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	core.cfg.AuthMode = ""
	ctx := t.Context()
	tenants := []string{freshTenant(t, db, "inbox-pages-a"), freshTenant(t, db, "inbox-pages-b")}
	f := &tagImportSubjectFixture{srv: core, db: db, a: tenants[0], b: tenants[1]}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	proofs := make([]*reportDownloadProof, 2)
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	for lane, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "inbox@"+tenant+".invalid", "Inbox owner")
			if err != nil {
				return err
			}
			role, err := (store.Roles{}).Create(ctx, sc, "inbox-owner", "Inbox owner", "Complete retained metadata")
			if err != nil {
				return err
			}
			for _, permission := range []string{"metrics.read", permAIQuery, permFlowRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
				return err
			}
			token, err := auth.RandomToken()
			if err != nil {
				return err
			}
			proofs[lane] = &reportDownloadProof{tenant: tenant, user: user.ID, token: token, role: role.ID}
			if _, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "same-inbox", OwnerID: user.ID, Name: "Inbox", Preset: "operator", Definition: []byte(`{}`)}); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
 (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,generated_at,absolute_from,absolute_to,redaction_state)
 SELECT $1,'report-'||lpad(n::text,4,'0'),'same-inbox','csv','text/csv',$3||lpad(n::text,4,'0')||'.csv',$4,$2,$5,$5::timestamptz-interval '1 hour',$5,'none'
 FROM generate_series(1,501) n`, tenant, user.ID, fmt.Sprintf("private-lane%d-", lane), []byte("body-not-metadata"), stamp); err != nil {
				return err
			}
			// Unconfigured/invalid source envelopes remain hidden. More than one
			// SQL batch precedes the first authorized metadata in the same snapshot.
			_, err = sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
 (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,generated_at,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
 SELECT $1,'hidden-'||n::text,'same-inbox','csv','text/csv','hidden-source.csv',NULL,$2,$3::timestamptz+interval '1 hour',$3::timestamptz-interval '1 hour',$3,'none','chunks',1,decode(repeat('00',32),'hex'),jsonb_build_object('version',1,'tenant_id',$1::uuid::text)
 FROM generate_series(1,220) n`, tenant, user.ID, stamp)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if _, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(bound, tenant, proofs[lane].user, "inbox-reader", crypto.Hash([]byte(proofs[lane].token)), stamp.Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		consentCapturedReportMCP(t, f, proofs[lane])
	}
	rest := httptest.NewTLSServer(core.Handler())
	defer rest.Close()
	ca := filepath.Join(t.TempDir(), "qa-inbox-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rest.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	native := NewMCPServerWithPolicyLoader(cfg, core.log, core.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, core.log, core.pool), nil, nil, core.MCPPolicyLoader(), AISources{NativeFlow: core})
	mcpSocket := httptest.NewTLSServer(native.HTTPHandler(NewMCPAuthenticator(core.pool, NewTenantStatusCache(core.pool, 0), false)))
	defer mcpSocket.Close()
	type page struct {
		Items      []reportArtifactView `json:"items"`
		NextCursor string               `json:"next_cursor"`
	}
	get := func(lane int, cursor string, limit int) (page, int, []byte) {
		t.Helper()
		query := url.Values{}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		if limit > 0 {
			query.Set("limit", fmt.Sprint(limit))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rest.URL+"/v1/dashboard-report-artifacts?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+proofs[lane].token)
		response, err := rest.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result page
		if response.StatusCode == http.StatusOK && json.Unmarshal(raw, &result) != nil {
			t.Fatal("inbox response malformed")
		}
		return result, response.StatusCode, raw
	}
	var firstCursor string
	for lane := range tenants {
		first, status, _ := get(lane, "", 0)
		if status != http.StatusOK || len(first.Items) != 200 || first.NextCursor == "" {
			t.Fatal("default inbox page is not a complete physical batch", status, len(first.Items))
		}
		if lane == 0 {
			firstCursor = first.NextCursor
		}
		seen := map[string]bool{}
		cursor := ""
		for pages := 0; pages < 5; pages++ {
			result, status, raw := get(lane, cursor, 250)
			if status != http.StatusOK || bytes.Contains(raw, []byte("hidden-")) || bytes.Contains(raw, []byte("body-not-metadata")) || bytes.Contains(raw, []byte(fmt.Sprintf("private-lane%d-", 1-lane))) {
				t.Fatal("inbox page leaked source/body/foreign metadata", status)
			}
			if pages == 0 && len(result.Items) != 250 {
				t.Fatal("inbox page retains former200record quota", len(result.Items))
			}
			for _, item := range result.Items {
				if seen[item.ID] {
					t.Fatal("inbox keyset repeated tied timestamp record")
				}
				seen[item.ID] = true
			}
			if result.NextCursor == "" {
				break
			}
			if result.NextCursor == cursor {
				t.Fatal("inbox cursor did not advance")
			}
			cursor = result.NextCursor
		}
		if len(seen) != 501 {
			t.Fatal("complete inbox retained history narrowed", lane, len(seen))
		}
		client := reportMCPClient{t: t, socket: mcpSocket, foreignTenant: tenants[1-lane]}
		var nativePage mcp.ReportArtifactList
		client.call(proofs[lane].token, "report_artifacts", map[string]any{"limit": 250}, &nativePage, true, "native inbox first page failed")
		if len(nativePage.Items) != 250 || nativePage.NextCursor == "" {
			t.Fatal("native inbox did not carry complete page and continuation")
		}
		client.call(proofs[lane].token, "report_artifacts", map[string]any{"limit": 250, "cursor": nativePage.NextCursor}, &nativePage, true, "native inbox continuation failed")
		if len(nativePage.Items) != 250 {
			t.Fatal("native inbox continuation lost complete page")
		}
		var out, errs bytes.Buffer
		env := func(key string) string {
			switch key {
			case "PROBECTL_API_URL":
				return rest.URL
			case "PROBECTL_CA_FILE":
				return ca
			case "PROBECTL_API_TOKEN":
				return proofs[lane].token
			}
			return ""
		}
		if code := cli.RunWithStdin([]string{"--json", "dashboard-report", "artifacts", "--query", "limit=250", "--query", "cursor=" + first.NextCursor}, env, strings.NewReader(""), &out, &errs); code != 0 {
			t.Fatal("TLS CLI inbox continuation refused", code, errs.String())
		}
		var cliPage page
		if json.Unmarshal(out.Bytes(), &cliPage) != nil || len(cliPage.Items) != 250 || cliPage.Items[0].ID == first.Items[0].ID {
			t.Fatal("TLS CLI narrowed inbox page/continuation")
		}
	}
	if _, status, raw := get(1, firstCursor, 250); status == http.StatusOK || bytes.Contains(raw, []byte("private-lane")) {
		t.Fatal("foreign cursor disclosed metadata", status)
	}
	for _, bad := range []string{"not-a-cursor", "e30", "bnVsbA"} {
		if _, status, _ := get(0, bad, 250); status == http.StatusOK {
			t.Fatal("malformed cursor became an inbox grant")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	request := httptest.NewRequest(http.MethodGet, "/v1/dashboard-report-artifacts", nil).WithContext(auth.WithPrincipal(tenancy.WithTenant(canceled, tenancy.ID(tenants[0])), &auth.Principal{TenantID: tenants[0], UserID: proofs[0].user}))
	recorder := httptest.NewRecorder()
	if err := core.listCurrentReportArtifactMetadata(recorder, request); err == nil || recorder.Body.Len() != 0 {
		t.Fatal("canceled inbox operation returned partial metadata", err)
	}
}
