// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveIncidentVerdictSignedExport(t *testing.T, f *roleExplanationAPIFixture, tenant, id string, input incident.VerdictInput, expected incident.FaultVerdict) {
	t.Helper()
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(private)
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency, policy.QueriesPerMin = 1, 10000
	f.server.WithFairness(fairness.NewGate(policy, nil))
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, permission := range []string{permAIQuery, permFlowRead} {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
				return err
			}
		}
		return nil
	})
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "export-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	want, err := redactIncidentVerdict(expected, redactionPolicy(f.server.cfg), tenant)
	if err != nil {
		t.Fatal(err)
	}
	assert := func(raw []byte, combined bool) {
		t.Helper()
		manifest, err := evidence.Verify(raw)
		if err != nil || manifest == nil {
			t.Fatal("signed export failed offline verification", err)
		}
		var pkg evidence.Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatal(err)
		}
		if pkg.Signing.PublicKey != string(public) || bytes.Contains(raw, []byte(tenant)) || manifest.Incident.ID != id {
			t.Fatal("export lost signer, opaque tenant scope or incident binding")
		}
		found, impact := 0, false
		for _, record := range manifest.Evidence {
			if record.Kind == "incident.impact" {
				impact = true
			}
			if record.Kind != "incident.fault_domain" {
				continue
			}
			for _, attachment := range pkg.Attachments {
				if attachment.Digest != record.AttachmentDigest {
					continue
				}
				found++
				var got incident.FaultVerdict
				if err := json.Unmarshal(attachment.Content, &got); err != nil {
					t.Fatal(err)
				}
				wanted := want
				wanted.EvaluatedAt = got.EvaluatedAt
				if !reflect.DeepEqual(got, wanted) {
					t.Fatal("signed verdict changed window, hypotheses, citations or original authority deadline")
				}
			}
		}
		if found != 1 || impact != combined {
			t.Fatal("export omitted or duplicated selected evidence", found, impact, combined)
		}
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	selection := &sdk.IncidentEvidenceExportInput{Verdict: &sdk.IncidentVerdictInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}}
	for _, combined := range []bool{false, true} {
		if combined {
			selection.Impact = &sdk.IncidentImpactInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}
		}
		raw, err := client.ExportIncidentEvidenceBytes(t.Context(), sdk.ExportIncidentEvidenceBytesRequest{Id: id, Body: selection})
		if err != nil {
			t.Fatal("byte-preserving SDK export failed", combined, err)
		}
		assert(raw, combined)
	}
	body, err := json.Marshal(incidentEvidenceExportInput{Verdict: &input})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "incident", "export", id, "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr); code != 0 {
		t.Fatal("verified TLS signed verdict CLI failed", code, stderr.String())
	}
	assert(stdout.Bytes(), false)
	proveIncidentExportPermissionWithdrawal(t, f, tenant, id, input)
}

func proveIncidentExportPermissionWithdrawal(t *testing.T, f *roleExplanationAPIFixture, tenant, id string, input incident.VerdictInput) {
	t.Helper()
	var actor *auth.Principal
	var inc *incident.Incident
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
		if err != nil {
			return err
		}
		actor = auth.ClonePrincipal(current.principal)
		inc, err = (store.Incidents{}).Get(ctx, sc, id)
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	var verdict, impact incidentEvidenceFinalizer
	if _, err := f.server.exportIncidentVerdict(ctx, actor, inc, input, 0, &verdict); err != nil {
		t.Fatal("prepare verdict publication", err)
	}
	if _, err := f.server.exportIncidentImpact(ctx, actor, inc, incident.ImpactInput{From: input.From, To: input.To}, &impact); err != nil {
		t.Fatal("prepare impact publication", err)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permAIQuery)
		return err
	})
	// The final call deliberately has no export-purpose context flag. Each
	// callback must preserve that purpose and recheck current AI permission.
	for _, check := range []incidentEvidenceFinalizer{verdict, impact} {
		if check == nil || check(ctx) == nil {
			t.Fatal("permission withdrawn after computation retained signed publication authority")
		}
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAIQuery)
	})
}
