//go:build integration

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNMSImportDDoSPrefixPreviewApplyAndReimportStayTenantScoped(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permNMSImportRead, permNMSImportWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, sample := range []struct{ source, resource, network string }{
		{"sightline", "managed_objects", "192.0.2.0/24"},
		{"defenseflow", "protected_objects", "2001:db8::/48"},
	} {
		t.Run(sample.source, func(t *testing.T) {
			call := func(actor, method, route string, body any, status int) []byte {
				t.Helper()
				return callSeasonalAPI(t, socket, f.tokens[actor], method, route, body, status)
			}
			prepare := func(tenant, label, action, target string) (string, string, string) {
				t.Helper()
				var plan struct {
					ID string `json:"plan_id"`
				}
				start := call(tenant, http.MethodPost, "/v1/nms-imports/export-plans",
					map[string]string{"context_id": f.contextID, "source_kind": sample.source, "instance_ref": "owned-lab"}, http.StatusCreated)
				if json.Unmarshal(start, &plan) != nil || plan.ID == "" {
					t.Fatal("preview plan did not return its ID", string(start))
				}
				base := "/v1/nms-imports/" + plan.ID
				query := "?context_id=" + f.contextID
				path := base + "/export-pages" + query + "&resource=" + sample.resource + "&page_number=0&first_row=0"
				body := nmsDDoSPrefixUpload(t, sample.source, label, sample.network)
				for _, sibling := range f.tenants {
					if sibling != tenant {
						call(sibling, http.MethodPost, path, body, http.StatusNotFound)
					}
				}
				receipt := call(tenant, http.MethodPost, path, body, http.StatusOK)
				replay := call(tenant, http.MethodPost, path, body, http.StatusOK)
				if !bytes.Equal(receipt, replay) || !bytes.Contains(receipt, []byte(`"row_count":1`)) {
					t.Fatal("exact source page receipt changed", string(receipt), string(replay))
				}
				call(tenant, http.MethodPost, path, nmsDDoSPrefixUpload(t, sample.source, "Different", sample.network), http.StatusBadRequest)
				closed := call(tenant, http.MethodPost, base+"/export-seal",
					map[string]any{"context_id": f.contextID, "expected_pages": 1, "expected_rows": 1}, http.StatusOK)
				var sealed struct {
					Hash string `json:"snapshot_hash"`
				}
				if json.Unmarshal(closed, &sealed) != nil || len(sealed.Hash) != 64 {
					t.Fatal("snapshot was not sealed", string(closed))
				}
				rows := call(tenant, http.MethodGet, base+"/rows"+query, nil, http.StatusOK)
				var page nmsimport.SealedRowsPage
				if json.Unmarshal(rows, &page) != nil || len(page.Items) != 1 || page.Items[0].Address != sample.network ||
					page.Items[0].ExternalID != "same-object|"+sample.network || page.Items[0].Label != label ||
					len(page.Items[0].SourceMappingDigest) != 64 || bytes.Contains(rows, []byte("discard-fixture")) {
					t.Fatal("preview did not preserve only normalized source fields", string(rows))
				}
				call(tenant, http.MethodPost, base+"/review-choices", map[string]any{
					"context_id": f.contextID, "snapshot_hash": sealed.Hash,
					"choices": []nmsimport.ReviewChoice{{RowNumber: 0, Action: action, TargetEntityID: target}},
				}, http.StatusNoContent)
				frozen := call(tenant, http.MethodPost, base+"/finalize-review",
					map[string]string{"context_id": f.contextID, "snapshot_hash": sealed.Hash}, http.StatusOK)
				var reviewed struct {
					Hash string `json:"review_hash"`
				}
				if json.Unmarshal(frozen, &reviewed) != nil || len(reviewed.Hash) != 64 {
					t.Fatal("review was not frozen", string(frozen))
				}
				diff := call(tenant, http.MethodGet, base+"/dry-run"+query+"&review_hash="+reviewed.Hash, nil, http.StatusOK)
				if !bytes.Contains(diff, []byte(`"proposed_network_prefix":"`+sample.network+`"`)) {
					t.Fatal("dry run omitted the exact network", string(diff))
				}
				return base, sealed.Hash, reviewed.Hash
			}
			actorEntity := map[string]string{}
			for lane, tenant := range f.tenants {
				label := []string{"Owned Blue", "Owned Green"}[lane]
				for attempt := range 2 {
					base, snapshot, review := prepare(tenant, label, "create", "")
					input := map[string]string{"context_id": f.contextID, "snapshot_hash": snapshot, "review_hash": review}
					call(f.tenants[1-lane], http.MethodPost, base+"/apply", input, http.StatusNotFound)
					result := call(tenant, http.MethodPost, base+"/apply", input, http.StatusOK)
					if !bytes.Contains(result, []byte(`"state":"applied"`)) {
						t.Fatal("apply did not finish the human-reviewed plan", string(result))
					}
					var destination string
					var count int
					f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
						return sc.Q.QueryRow(ctx, `SELECT count(*),coalesce(min(id::text),'') FROM entities
							WHERE tenant_id=$1 AND context_id=$2 AND kind='prefix' AND label=$3 AND network_prefix=$4::cidr`,
							tenant, f.contextID, label, sample.network).Scan(&count, &destination)
					})
					if count != 1 || attempt != 0 && destination != actorEntity[tenant] {
						t.Fatal("repeat import changed canonical binding or created a duplicate", count, destination)
					}
					actorEntity[tenant] = destination
				}
			}
			if actorEntity[f.tenants[0]] == actorEntity[f.tenants[1]] {
				t.Fatal("overlapping source keys selected one canonical prefix across tenants")
			}
		})
	}
}

func nmsDDoSPrefixUpload(t *testing.T, source, label, prefix string) map[string]any {
	t.Helper()
	fields := map[string]string{"external_id": "key", "label": "name", "prefix": "network"}
	csv := "key,name,network,private\nsame-object," + label + "," + prefix + ",discard-fixture\n"
	if source == "sightline" {
		return map[string]any{"csv": csv, "column_mapping": fields}
	}
	const member = "local-fixture/objects.csv"
	var archive bytes.Buffer
	zipper := zip.NewWriter(&archive)
	file, err := zipper.Create(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(csv)); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"configuration_zip_base64": base64.StdEncoding.EncodeToString(archive.Bytes()),
		"member": member, "format": "csv", "field_mapping": fields}
}
