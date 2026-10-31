// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type retainedFlowFixture struct {
	*flowstore.Memory
	failed bool
}

func (f *retainedFlowFixture) ExportRetainedTenant(ctx context.Context, tenant string, w io.Writer) (int64, error) {
	return f.ExportRetainedSubject(ctx, tenant, "", w)
}
func (f *retainedFlowFixture) ExportRetainedSubject(ctx context.Context, tenant, subject string, w io.Writer) (int64, error) {
	if f.failed {
		return 0, errors.New("retained export unavailable")
	}
	records := map[string][]struct {
		subject string
		row     map[string]any
	}{
		"tnA": {{"alice", map[string]any{"tenant_id": "tnA", "agent_id": "alice", "src_addr": "10.0.0.5", "coverage_version": 1, "bytes_scaled": "9007199254740993", "subject_keys": []string{"alice", "10.0.0.5"}}}, {"legacy", map[string]any{"tenant_id": "tnA", "src_addr": "10.0.0.6", "coverage_version": 0, "subject_keys": []string{"legacy", "10.0.0.6"}}}},
		"tnB": {{"alice", map[string]any{"tenant_id": "tnB", "agent_id": "alice", "src_addr": "203.0.113.8", "coverage_version": 1, "subject_keys": []string{"alice", "203.0.113.8"}}}},
	}
	var count int64
	for _, item := range records[tenant] {
		if subject != "" && item.subject != subject {
			continue
		}
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if err := json.NewEncoder(w).Encode(item.row); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func TestRetainedFlowPortabilityBundleAndSubjectStayScopedAndRedacted(t *testing.T) {
	defer govern.Reset()
	fixture := &retainedFlowFixture{Memory: flowstore.NewMemory()}
	engine := New(nil, flowstore.WithTenantWriteFence(fixture, nil), nil, nil, (&capturedAudit{}).sink, "", testLog()).WithClock(func() time.Time { return t0 })
	var plain bytes.Buffer
	manifest, err := engine.Export(t.Context(), "tnA", &plain)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RetainedFlows != 2 || manifest.Flows != 0 {
		t.Fatalf("physical counts=%+v", manifest)
	}
	data := fileFromBundle(t, &plain, "flow_rollups.jsonl")
	if !bytes.Contains(data, []byte("9007199254740993")) || bytes.Contains(data, []byte("203.0.113.8")) || !bytes.Contains(data, []byte(`"coverage_version":0`)) {
		t.Fatalf("wrong retained bundle: %s", data)
	}
	var redacted bytes.Buffer
	if _, err := engine.ExportRedacted(t.Context(), "tnA", &redacted, true); err != nil {
		t.Fatal(err)
	}
	data = fileFromBundle(t, &redacted, "flow_rollups.jsonl")
	if bytes.Contains(data, []byte("10.0.0.5")) || !bytes.Contains(data, []byte(`"subject_keys":null`)) || !bytes.Contains(data, []byte("9007199254740993")) {
		t.Fatalf("retained redaction: %s", data)
	}
	var subject bytes.Buffer
	subjectManifest, err := engine.ExportSubject(t.Context(), "tnA", "alice", &subject, false)
	if err != nil {
		t.Fatal(err)
	}
	data = fileFromBundle(t, &subject, "flow_rollups.jsonl")
	if !bytes.Contains(data, []byte("10.0.0.5")) || bytes.Contains(data, []byte("10.0.0.6")) || bytes.Contains(data, []byte("203.0.113.8")) {
		t.Fatalf("subject scope: %s", data)
	}
	found := false
	for _, plane := range subjectManifest.Planes {
		if plane.Plane == "flow_rollups" {
			found = plane.Rows == 1 && plane.Status == SubjectStatusExported
		}
	}
	if !found {
		t.Fatalf("subject retained count missing: %+v", subjectManifest)
	}
	fixture.failed = true
	if _, err := engine.Export(t.Context(), "tnA", io.Discard); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("incomplete retained export must refuse: %v", err)
	}
}
