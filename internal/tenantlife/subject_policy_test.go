// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type subjectPolicyFlowReader struct {
	flowstore.Store
	tenants []string
}

func (s *subjectPolicyFlowReader) ExportTenant(ctx context.Context, tenant string, w io.Writer) (int64, error) {
	s.tenants = append(s.tenants, tenant)
	return s.Store.ExportTenant(ctx, tenant, w)
}

func TestSubjectExportGovernanceFailureNeverEmitsData(t *testing.T) {
	t.Cleanup(govern.Reset)
	const subject = "owned-subject@example.test"
	memory := flowstore.NewMemory()
	if err := memory.Insert(t.Context(), []flowstore.Row{
		{TenantID: "owned-red", AgentID: subject, TS: t0, SrcAddr: "198.51.100.17", DstAddr: "203.0.113.8", Bytes: 64},
		{TenantID: "owned-blue", AgentID: subject, TS: t0, SrcAddr: "192.0.2.77", DstAddr: "203.0.113.99", Bytes: 128},
	}); err != nil {
		t.Fatal(err)
	}
	flows := &subjectPolicyFlowReader{Store: memory}
	engine := New(nil, flows, nil, nil, (&capturedAudit{}).sink, "owned fixture backups", testLog())
	govern.SetSource(failGovern{})
	var refused bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), "owned-red", subject, &refused, false); err == nil || refused.Len() != 0 || len(flows.tenants) != 0 {
		t.Errorf("unreadable governance policy allowed subject source/export:err=%v bytes=%d reads=%v", err, refused.Len(), flows.tenants)
	}
	govern.SetSource(forceRedact{})
	var redacted bytes.Buffer
	manifest, err := engine.ExportSubject(t.Context(), "owned-red", subject, &redacted, false)
	if err != nil || !manifest.Redacted {
		t.Fatal("known force-redaction policy did not produce a redacted export", err)
	}
	row := flowsFromBundle(t, bytes.NewBuffer(redacted.Bytes()))
	if row["src_addr"] != "198.51.100.0/24" || row["dst_addr"] != "203.0.113.0/24" || row["bytes"] != float64(64) {
		t.Fatal("known-policy subject redaction changed", row)
	}
	body := readTarGz(t, redacted.Bytes())["flows.jsonl"]
	if strings.Contains(body, "owned-blue") || strings.Count(strings.TrimSpace(body), "\n") != 0 {
		t.Fatal("subject export included another tenant or unexpected row")
	}
	govern.Reset()
	var plain bytes.Buffer
	manifest, err = engine.ExportSubject(t.Context(), "owned-red", subject, &plain, false)
	if err != nil || manifest.Redacted || flowsFromBundle(t, &plain)["src_addr"] != "198.51.100.17" {
		t.Fatal("absent optional policy was treated as a failed policy source", err)
	}
	for _, tenant := range flows.tenants {
		if tenant != "owned-red" {
			t.Fatal("subject reader selected another tenant", tenant)
		}
	}
}
