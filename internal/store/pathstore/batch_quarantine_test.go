// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-362 (D-62): a write-behind flush holds every tenant's paths. When the
// router refuses one tenant (quarantined), only that tenant's paths are
// refused: the co-batched tenants' paths are still stored and counted saved.
// Before, SaveBatch returned on the first routing failure and the batcher
// logged the WHOLE batch as lost.
func TestPathBatchRefusesOnlyTheQuarantinedTenant(t *testing.T) {
	var mu sync.Mutex
	var inserted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO probectl_path_hops") {
			mu.Lock()
			inserted = append(inserted, string(b))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch, err := newClickHouse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := tenancy.NewQuarantine()
	q.Enter(tenancy.QuarantineEntry{TenantID: "tenant-q", Reason: tenancy.QuarantinePlaneUnreachable, Plane: "eu"})
	ch.WithRouter(func(_ context.Context, tenantID string) (Target, error) {
		if err := q.Check(tenantID); err != nil {
			return Target{}, err
		}
		return Target{}, nil
	})

	err = ch.SaveBatch(context.Background(), []PathItem{
		{TenantID: "tenant-a", P: samplePath()},
		{TenantID: "tenant-q", P: samplePath()},
		{TenantID: "tenant-b", P: samplePath()},
	})
	var partial *PartialBatchError
	if !errors.As(err, &partial) || partial.Refused != 1 || !errors.Is(err, tenancy.ErrTenantQuarantined) {
		t.Fatalf("SaveBatch = %v, want a partial refusal of the quarantined tenant only", err)
	}
	mu.Lock()
	body := strings.Join(inserted, "")
	mu.Unlock()
	if !strings.Contains(body, "tenant-a") || !strings.Contains(body, "tenant-b") || strings.Contains(body, "tenant-q") {
		t.Fatalf("stored rows = %q, want tenant-a and tenant-b only", body)
	}

	batching := NewBatchingSaver(ch, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, 100)
	defer func() { _ = batching.Close() }()
	for _, id := range []string{"tenant-a", "tenant-q", "tenant-b"} {
		if err := batching.Save(context.Background(), id, samplePath()); err != nil {
			t.Fatal(err)
		}
	}
	batching.Flush(context.Background())
	if saved, lost := batching.saved.Load(), batching.lostCount(); saved != 2 || lost != 1 {
		t.Fatalf("batcher saved=%d lost=%d, want 2 saved and only the quarantined tenant's 1 lost", saved, lost)
	}
}
