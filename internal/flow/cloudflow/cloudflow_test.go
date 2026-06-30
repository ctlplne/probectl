// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cloudflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
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
	conn := NewConnector(store, "cloud-agent-1")
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
		n, err := conn.Load(ctx, tc.provider, "tenant-a", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s load: %v", tc.provider, err)
		}
		if n != 1 {
			t.Fatalf("%s inserted %d rows, want 1", tc.provider, n)
		}
	}

	foreign := []byte("2 123456789012 eni-foreign 172.16.0.10 172.16.0.11 44444 443 6 1000 9000000 1782820800 1782820860 ACCEPT OK\n")
	if n, err := conn.Load(ctx, ProviderAWSVPC, "tenant-b", bytes.NewReader(foreign)); err != nil || n != 1 {
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
	n, err := Emit(context.Background(), ProviderAWSVPC, "tenant-a", "agent-cloud", bytes.NewReader(readFixture(t, "aws-vpc-flow.log")), em)
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
	conn := NewConnector(flowstore.NewMemory(), "cloud-agent-1")
	_, err := conn.Load(context.Background(), ProviderAWSVPC, "", strings.NewReader(""))
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("missing tenant must fail closed, got %v", err)
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
