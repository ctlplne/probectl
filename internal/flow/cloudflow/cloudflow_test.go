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
	"math"
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

	foreign := "2 123456789012 eni-foreign 172.16.0.10 172.16.0.11 44444 443 6 1000 9000000 1782820800 1782820860 ACCEPT OK\n" +
		"2 123456789012 eni-overflow 172.16.0.12 172.16.0.11 44444 443 6 1000 9000000 1782820800 9223372037 ACCEPT OK\n"
	if n, malformed, err := conn.load(ctx, ProviderAWSVPC, "tenant-b", strings.NewReader(foreign)); err != nil || n != 1 || malformed != 1 {
		t.Fatalf("foreign tenant load inserted %d rows with %d malformed: %v", n, malformed, err)
	}
	overflow := bytes.ReplaceAll(readFixture(t, "gcp-vpc-flow.jsonl"), []byte("2026-06-30T12:04:00Z"), []byte("2262-04-11T23:47:16.854775808Z"))
	if n, malformed, err := conn.load(ctx, ProviderGCPVPC, "tenant-b", bytes.NewReader(overflow)); err != nil || n != 0 || malformed != 1 {
		t.Fatalf("out-of-range GCP clock inserted %d rows with %d malformed: %v", n, malformed, err)
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

func TestCloudImportTimestampsFitFlowNanoseconds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		parse   func(string) (time.Time, error)
		valid   map[string]int64
		invalid []string
	}{
		{
			name:  "epoch seconds",
			parse: parseUnixSeconds,
			valid: map[string]int64{
				"0":          0,
				"1757980800": 1_757_980_800_000_000_000,
				"9223372036": 9_223_372_036_000_000_000,
			},
			invalid: []string{"9223372037", "253402300799", "9223372036854775808", "18446744073709551615"},
		},
		{
			name:  "RFC3339",
			parse: parseRFC3339,
			valid: map[string]int64{
				"1677-09-21T00:12:43.145224192Z":      math.MinInt64,
				"1970-01-01T01:00:00+01:00":           0,
				"2262-04-12T00:47:16.854775807+01:00": math.MaxInt64,
			},
			invalid: []string{"1677-09-21T00:12:43.145224191Z", "2262-04-11T23:47:16.854775808Z"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range tc.invalid {
				if _, err := tc.parse(input); err == nil {
					t.Errorf("accepted an out-of-range timestamp %q", input)
				}
			}
			for input, want := range tc.valid {
				got, err := tc.parse(input)
				if err != nil || got.Location() != time.UTC || got.UnixNano() != want {
					t.Errorf("parse(%q) = %v, %v; want UTC at %d Unix nanoseconds", input, got, err, want)
				}
			}
		})
	}
	t.Run("GCP clock fields", func(t *testing.T) {
		var fixture gcpLogEntry
		if err := json.Unmarshal(readFixture(t, "gcp-vpc-flow.jsonl"), &fixture); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"observation", "start", "end"} {
			t.Run(field, func(t *testing.T) {
				entry := fixture
				const outside = "2262-04-11T23:47:16.854775808Z"
				switch field {
				case "observation":
					entry.Timestamp = outside
				case "start":
					entry.JSONPayload.StartTime = outside
				case "end":
					entry.JSONPayload.EndTime = outside
				}
				body, err := json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				emitter := &captureEmitter{}
				inserted, malformed, err := Emit(t.Context(), ProviderGCPVPC, "tenant-a", "cloud-agent", bytes.NewReader(body), emitter)
				if err != nil || inserted != 0 || malformed != 1 || len(emitter.recs) != 0 {
					t.Fatalf("GCP %s clock published %d records with %d malformed: %v", field, inserted, malformed, err)
				}
			})
		}
	})
}
