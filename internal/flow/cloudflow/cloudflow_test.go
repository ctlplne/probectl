// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type captureEmitter struct {
	recs []flow.Record
}

func (c *captureEmitter) Emit(_ context.Context, recs []flow.Record) error {
	c.recs = append(c.recs, recs...)
	return nil
}

func TestConnectorLoadsCloudFixturesAndKeepsTenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := flowstore.NewMemory()
	conn := newConnector(store, "cloud-agent-1")
	now := time.Date(2026, 6, 30, 12, 10, 0, 0, time.UTC)
	conn.now = func() time.Time { return now }

	for _, tc := range []struct {
		provider Provider
		fixture  string
	}{
		{ProviderAWSVPC, "aws-vpc-flow.log"},
		{ProviderAzureNSG, "azure-nsg-flow.jsonl"},
		{ProviderGCPVPC, "gcp-vpc-flow.jsonl"},
	} {
		raw := readFixture(t, tc.fixture)
		n, _, err := conn.load(ctx, tc.provider, "tenant-a", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s load: %v", tc.provider, err)
		}
		if n != 1 {
			t.Fatalf("%s inserted %d rows, want 1", tc.provider, n)
		}
	}

	foreign := []byte("2 123456789012 eni-foreign 172.16.0.10 172.16.0.11 44444 443 6 1000 9000000 1782820800 1782820860 ACCEPT OK\n")
	if n, _, err := conn.load(ctx, ProviderAWSVPC, "tenant-b", bytes.NewReader(foreign)); err != nil || n != 1 {
		t.Fatalf("foreign tenant load inserted %d rows: %v", n, err)
	}

	topA, err := store.TopTalkers(ctx, flowstore.TopQuery{
		TenantID: "tenant-a", By: flowstore.BySrc, Window: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatalf("tenant-a top talkers: %v", err)
	}
	if len(topA) != 3 {
		t.Fatalf("tenant-a top talkers = %+v, want three cloud fixture sources", topA)
	}
	for _, row := range topA {
		if strings.HasPrefix(row.Key, "172.16.") {
			t.Fatalf("CROSS-TENANT LEAK: tenant-a saw tenant-b row: %+v", topA)
		}
	}

	topB, err := store.TopTalkers(ctx, flowstore.TopQuery{
		TenantID: "tenant-b", By: flowstore.BySrc, Window: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatalf("tenant-b top talkers: %v", err)
	}
	if len(topB) != 1 || topB[0].Key != "172.16.0.10" || topB[0].Bytes != 9_000_000 {
		t.Fatalf("tenant-b isolation/top row = %+v", topB)
	}

	rows := exportRows(t, store, "tenant-a")
	seenProtocols := map[string]bool{}
	seenExporters := map[string]bool{}
	for _, row := range rows {
		seenProtocols[row.Protocol] = true
		switch {
		case strings.HasPrefix(row.Exporter, "aws:eni-"):
			seenExporters["aws"] = true
		case strings.HasPrefix(row.Exporter, "azure:/subscriptions/"):
			seenExporters["azure"] = true
		case strings.HasPrefix(row.Exporter, "gcp:subnet-"):
			seenExporters["gcp"] = true
		}
	}
	for _, proto := range []string{
		flow.ProtoAWSVPCFlowLogs,
		flow.ProtoAzureNSGFlowLogs,
		flow.ProtoGCPVPCFlowLogs,
	} {
		if !seenProtocols[proto] {
			t.Fatalf("missing normalized protocol %s in exported rows: %+v", proto, rows)
		}
	}
	for _, cloud := range []string{"aws", "azure", "gcp"} {
		if !seenExporters[cloud] {
			t.Fatalf("missing %s exporter provenance in exported rows: %+v", cloud, rows)
		}
	}
}

func TestEmitPublishesTenantBoundCloudRecords(t *testing.T) {
	em := &captureEmitter{}
	n, _, err := Emit(context.Background(), ProviderAWSVPC, "tenant-a", "agent-cloud", bytes.NewReader(readFixture(t, "aws-vpc-flow.log")), em)
	if err != nil {
		t.Fatalf("emit cloud flow: %v", err)
	}
	if n != 1 || len(em.recs) != 1 {
		t.Fatalf("emitted n=%d records=%+v, want one", n, em.recs)
	}
	rec := em.recs[0]
	if rec.TenantID != "tenant-a" || rec.AgentID != "agent-cloud" || rec.Protocol != flow.ProtoAWSVPCFlowLogs {
		t.Fatalf("record was not tenant/agent/protocol bound: %+v", rec)
	}
}

func TestConnectorRefusesMissingTenant(t *testing.T) {
	conn := newConnector(flowstore.NewMemory(), "cloud-agent-1")
	_, _, err := conn.load(context.Background(), ProviderAWSVPC, "", strings.NewReader(""))
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("missing tenant must fail closed, got %v", err)
	}
}

// TestCloudflowDoesNotCountDeniedFlowsAsTraffic (ING-41) drives the real
// import path (Emit → scan → decodeLine → the AWS/Azure decoders) and asserts
// that a denied flow is distinguishable from an allowed one: a REJECT (AWS) or
// a "D" decision (Azure) must NOT be imported as delivered traffic, while an
// ACCEPT/allow flow still imports as one traffic record.
//
// Before the fix this failed: the AWS decoder checked only the log-status field
// (OK), not the ACCEPT/REJECT action, so a REJECT line with log-status OK
// imported indistinguishably from an ACCEPT; the Azure decoder never read the
// A/D decision at all, so a deny tuple imported indistinguishably from allow.
func TestCloudflowDoesNotCountDeniedFlowsAsTraffic(t *testing.T) {
	// AWS VPC default format: field 12 = action (ACCEPT/REJECT),
	// field 13 = log-status (OK). Both lines are log-status OK so the only
	// difference under test is the action.
	const (
		awsAccept = "2 123456789012 eni-0abc1234 10.10.0.5 10.20.0.9 51514 443 6 11 2048 1782820800 1782820860 ACCEPT OK"
		awsReject = "2 123456789012 eni-0abc1234 10.10.0.5 10.20.0.9 51514 443 6 11 2048 1782820800 1782820860 REJECT OK"
	)
	// Azure NSG v2 tuple: part 7 = traffic decision ("A" allow / "D" deny).
	// Everything but that field is identical between the two lines.
	azureLine := func(decision string) string {
		return `{"records":[{"time":"2026-06-30T12:02:00Z","resourceId":"/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-prod","properties":{"Version":2,"flows":[{"rule":"Rule","flows":[{"mac":"000D3A123456","flowTuples":["1782820920,10.10.0.6,20.20.20.20,53000,443,T,O,` + decision + `,B,7,4096,2,1024"]}]}]}}]}`
	}

	for _, tc := range []struct {
		name      string
		provider  Provider
		line      string
		delivered bool // true: ACCEPT/allow, must import as traffic; false: denied, must not be counted
	}{
		{"aws_accept_imports_as_traffic", ProviderAWSVPC, awsAccept, true},
		{"aws_reject_is_not_counted", ProviderAWSVPC, awsReject, false},
		{"azure_allow_imports_as_traffic", ProviderAzureNSG, azureLine("A"), true},
		{"azure_deny_is_not_counted", ProviderAzureNSG, azureLine("D"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := &captureEmitter{}
			n, _, err := Emit(context.Background(), tc.provider, "tenant-a", "agent-cloud", strings.NewReader(tc.line), em)
			if err != nil {
				t.Fatalf("emit %s: %v", tc.provider, err)
			}
			if tc.delivered {
				if n != 1 || len(em.recs) != 1 {
					t.Fatalf("an ACCEPT/allow flow must import as one traffic record, got n=%d recs=%d", n, len(em.recs))
				}
				if em.recs[0].Bytes == 0 {
					t.Fatalf("delivered flow imported with zero bytes, not counted as traffic: %+v", em.recs[0])
				}
			} else if n != 0 || len(em.recs) != 0 {
				t.Fatalf("a REJECT/deny flow must NOT be counted as delivered traffic, but it imported n=%d recs=%d (indistinguishable from ACCEPT/allow)", n, len(em.recs))
			}
		})
	}
}

// TestCloudflowSkipsMalformedLinesAndAcceptsGzip (RTP-20) drives the real
// import path (Emit → scan) and asserts two things the connector got wrong:
//
//  1. A single malformed line in the middle of a file must be SKIPPED and
//     counted, not abort the whole import. Before the fix, scan returned an
//     error on the first bad line, which discarded every valid line — including
//     the ones already buffered in pending but never flushed (flush only fires
//     at 1000 records or at a clean end that the abort prevented). So a
//     valid/garbage/valid file imported ZERO records.
//  2. A gzip-compressed export (how AWS delivers VPC flow logs to S3 as
//     .log.gz) must import the same as the uncompressed bytes. Before the fix,
//     scan read the raw gzip bytes as text lines, which failed to parse and
//     aborted with zero records stored.
//
// The all_valid case is the non-vacuity guard: the skip path must not be
// masking a total failure to import.
func TestCloudflowSkipsMalformedLinesAndAcceptsGzip(t *testing.T) {
	// Two valid AWS VPC default-format lines (field 12 ACCEPT, field 13 OK) and
	// one line that cannot be decoded (far fewer than the 14 required fields).
	const (
		valid1  = "2 123456789012 eni-0abc1234 10.10.0.5 10.20.0.9 51514 443 6 11 2048 1782820800 1782820860 ACCEPT OK"
		valid2  = "2 123456789012 eni-0def5678 10.10.0.6 10.20.0.10 51515 443 6 22 4096 1782820800 1782820860 ACCEPT OK"
		garbage = "this-is-not-a-valid-aws-vpc-flow-log-line"
	)
	allValid := valid1 + "\n" + valid2 + "\n"
	validGarbageValid := valid1 + "\n" + garbage + "\n" + valid2 + "\n"

	gzipBytes := func(t *testing.T, s string) []byte {
		t.Helper()
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write([]byte(s)); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		return buf.Bytes()
	}

	for _, tc := range []struct {
		name          string
		input         []byte
		wantInserted  int
		wantMalformed int
	}{
		// Non-vacuity: an all-valid file must import every line.
		{"all_valid_imports_fully", []byte(allValid), 2, 0},
		// The RTP-20 regression: a bad line between two good ones skips one and
		// keeps both valid lines. Fails before the fix (aborts at line 2, 0 stored).
		{"valid_garbage_valid_skips_one_and_imports_the_rest", []byte(validGarbageValid), 2, 1},
		// Gzip input must import the same as plain. Fails before the fix (the gzip
		// bytes are scanned as text and never parse).
		{"gzip_valid_imports_same_as_plain", gzipBytes(t, allValid), 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := &captureEmitter{}
			inserted, malformed, err := Emit(context.Background(), ProviderAWSVPC, "tenant-a", "agent-cloud", bytes.NewReader(tc.input), em)
			if err != nil {
				t.Fatalf("import aborted with error, but RTP-20 requires a bad line or gzip input to import without aborting: %v", err)
			}
			if inserted != tc.wantInserted {
				t.Fatalf("inserted=%d, want %d: valid lines before and after a malformed line (or inside a gzip export) must still import", inserted, tc.wantInserted)
			}
			if len(em.recs) != tc.wantInserted {
				t.Fatalf("emitted %d records, want %d", len(em.recs), tc.wantInserted)
			}
			if malformed != tc.wantMalformed {
				t.Fatalf("malformed=%d, want %d: malformed lines must be counted and reported", malformed, tc.wantMalformed)
			}
		})
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func exportRows(t *testing.T, store flowstore.Store, tenantID string) []flowstore.Row {
	t.Helper()
	var buf bytes.Buffer
	n, err := store.ExportTenant(context.Background(), tenantID, &buf)
	if err != nil {
		t.Fatalf("export tenant %s: %v", tenantID, err)
	}
	if n == 0 {
		t.Fatalf("export tenant %s returned no rows", tenantID)
	}
	dec := json.NewDecoder(&buf)
	var rows []flowstore.Row
	for {
		var row flowstore.Row
		err := dec.Decode(&row)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode exported row: %v", err)
		}
		rows = append(rows, row)
	}
	return rows
}

// TestParseUnixSecondsRejectsOutOfRange (DPR-246) is the CodeQL
// go/incorrect-integer-conversion finding on this file, made concrete.
//
// The field is a timestamp in a CLOUD PROVIDER's flow log — third-party content,
// which §7 guardrail 10 says is untrusted. It was parsed as uint64 and converted
// straight to int64 for time.Unix, so an out-of-range value did not fail to
// import; it imported with a nonsense timestamp. Measured on the unbounded code:
// 2^63 became 292277026596-12-04T15:30:08Z, and max uint64 (which is int64 -1)
// became 1969-12-31T23:59:59Z. Either way the record lands silently outside every
// retention and query window instead of being rejected as malformed.
func TestParseUnixSecondsRejectsOutOfRange(t *testing.T) {
	// 2^63 is a legal uint64 and a negative int64; unbounded, time.Unix turned it
	// into the year 292277026596.
	const wraps = "9223372036854775808" // 2^63
	if got, err := parseUnixSeconds(wraps); err == nil {
		t.Errorf("parseUnixSeconds(%s) = %s with no error; a value that wraps int64 must be refused",
			wraps, got.Format(time.RFC3339))
	}
	for _, in := range []string{
		"18446744073709551615", // max uint64
		"253402300800",         // one second past the bound
	} {
		if _, err := parseUnixSeconds(in); err == nil {
			t.Errorf("parseUnixSeconds(%s) accepted an out-of-range timestamp", in)
		}
	}
	// And the ordinary cases still work, including the exact bound.
	for in, want := range map[string]int64{
		"0":            0,
		"1757980800":   1757980800,
		"253402300799": 253402300799, // the bound itself is valid
	} {
		got, err := parseUnixSeconds(in)
		if err != nil {
			t.Errorf("parseUnixSeconds(%s) errored: %v", in, err)
			continue
		}
		if got.Unix() != want {
			t.Errorf("parseUnixSeconds(%s) = %d, want %d", in, got.Unix(), want)
		}
		if got.Location() != time.UTC {
			t.Errorf("parseUnixSeconds(%s) is not UTC: %s", in, got.Location())
		}
	}
}
