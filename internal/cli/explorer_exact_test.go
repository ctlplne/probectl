// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestExplorerCLIExactVersionRequestAndResponse(t *testing.T) {
	const version = "9007199254740993"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Contains(body, []byte(`"version":`+version)) {
			t.Errorf("rounded request: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"filter","version":`+version+`,"bytes:total_str":"18446744073709551615"}`)
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	env := func(k string) string {
		if k == "PROBECTL_API_URL" {
			return server.URL
		}
		return ""
	}
	input := `{"name":"exact","expression":{"conditions":[{"field":"dst_port","op":"eq","values":["443"]}]},"version":` + version + `}`
	code := RunWithStdin([]string{"--json", "explorer", "filter-update", "filter", "--body-file", "-"}, env, strings.NewReader(input), &out, &errs)
	if code != 0 || !strings.Contains(out.String(), version) || strings.Contains(out.String(), "9007199254740992") {
		t.Fatalf("code%d err%s out%s", code, errs.String(), out.String())
	}
}

func TestExplorerCLIQualifiedTagFieldsRemainExact(t *testing.T) {
	input := `{"source":"flow","flow":{"group_by":["tag.role","tag.device.role"],"matrix_with":["tag.agent.role"],"filter":{"conditions":[{"field":"tag.device.role","op":"eq","values":["edge"]}]}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var got, want any
		if json.Unmarshal(raw, &got) != nil || json.Unmarshal([]byte(input), &want) != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("qualified native grammar changed in CLI: %s", raw)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/explorer/query" {
			t.Errorf("qualified native plan changed in CLI: %s %s %s", r.Method, r.URL.Path, raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"flow":{"totals":{"bytes:total":"9007199254740993"}}}`)
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	env := func(key string) string {
		if key == "PROBECTL_API_URL" {
			return server.URL
		}
		return ""
	}
	code := RunWithStdin([]string{"--json", "explorer", "query", "--body-file", "-"}, env, strings.NewReader(input), &out, &errs)
	if code != 0 || !strings.Contains(out.String(), "9007199254740993") {
		t.Fatalf("code%d err%s out%s", code, errs.String(), out.String())
	}
}
