// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/opendata"
)

func TestPublishedServiceRangeCommandKeepsExplicitBulkOperationAndRaiseableAdmission(t *testing.T) {
	var output, stderr bytes.Buffer
	calls := 0
	fetch := func(_ context.Context, path string, sources []string, age time.Duration, memory int64, options opendata.ServiceRangeFetchOptions, client opendata.Doer) error {
		calls++
		httpClient, ok := client.(*http.Client)
		if path != "/operator/cache.json" || !reflect.DeepEqual(sources, []string{"aws", "google_cloud"}) || age != 72*time.Hour || memory != 8<<30 || !ok || options.Microsoft365ClientRequestID != "" || httpClient.Timeout != 37*time.Second {
			t.Fatal("command changed explicit source or admission", path, sources, age, memory)
		}
		return nil
	}
	args := []string{"--publishers", "aws,google_cloud", "--output", "/operator/cache.json", "--memory-bytes", "8589934592", "--max-age", "72h", "--timeout", "37s"}
	if code := cmdFetchServiceRanges(Config{JSON: true, Token: "must not leave", Tenant: "private-tenant"}, args, &output, &stderr, fetch); code != 0 || calls != 1 || !strings.Contains(output.String(), `"restart_required": true`) || strings.Contains(output.String(), "private-tenant") {
		t.Fatal("explicit bulk operation failed", code, output.String(), stderr.String())
	}
	for _, args := range [][]string{{"--help"}, {"--publishers", "aws"}, {"--output", "/operator/cache.json"}, {"--publishers", "aws", "--output", "/operator/cache.json", "--memory-bytes", "0"}} {
		before := calls
		cmdFetchServiceRanges(Config{}, args, &output, &stderr, fetch)
		if calls != before {
			t.Fatal("help or incomplete operation performed a public fetch")
		}
	}
	if code := cmdFetchServiceRanges(Config{}, args, &output, &stderr, func(context.Context, string, []string, time.Duration, int64, opendata.ServiceRangeFetchOptions, opendata.Doer) error {
		return errors.New("prior cache preserved")
	}); code != 1 {
		t.Fatal("fetch failure reported success", code)
	}
	output.Reset()
	stderr.Reset()
	if code := RunWithStdin([]string{"opendata", "fetch-ranges", "--help"}, func(string) string { return "" }, strings.NewReader(""), &output, &stderr); code != 0 || !strings.Contains(output.String(), "publishers") {
		t.Fatal("public help path failed", code, output.String(), stderr.String())
	}
}

func TestM365BulkCommandKeepsMachineAssociationSeparateFromTenantAndOutput(t *testing.T) {
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	fetch := func(_ context.Context, _ string, publishers []string, _ time.Duration, _ int64, options opendata.ServiceRangeFetchOptions, _ opendata.Doer) error {
		if !reflect.DeepEqual(publishers, []string{"m365"}) || options.Microsoft365ClientRequestID != id {
			t.Fatal("operator association was changed or omitted")
		}
		return nil
	}
	args := []string{"--publishers", "m365", "--m365-client-request-id", id, "--output", "/operator/cache.json"}
	if code := cmdFetchServiceRanges(Config{JSON: true, Token: "must not leave", Tenant: "private-tenant"}, args, &output, &stderr, fetch); code != 0 || strings.Contains(output.String(), id) || strings.Contains(output.String(), "private-tenant") {
		t.Fatal("explicit Microsoft365 source configuration leaked private context", code)
	}
}
