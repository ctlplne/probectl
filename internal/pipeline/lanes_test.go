// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// CORRECT-005: RunLanes must subscribe to the shared topic AND every siloed
// tenant's namespaced lane, invoking the handler with the lane's authoritative
// tenant ("" for the shared lane, the lane tenant for a namespaced one).
func TestRunLanesFansOutToSiloedTenants(t *testing.T) {
	b := bus.NewMemory()
	base := bus.NetworkResultsTopic
	nsTenants := map[string]string{"acme": "tenant-acme"}

	var mu sync.Mutex
	got := map[string]string{} // value -> laneTenant it arrived with

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = RunLanes(ctx, b, base, "test-grp", nsTenants, func(_ context.Context, m bus.Message, laneTenant string) error {
			mu.Lock()
			got[string(m.Value)] = laneTenant
			mu.Unlock()
			return nil
		})
		close(done)
	}()

	acmeTopic, err := bus.TopicFor("acme", base)
	if err != nil {
		t.Fatal(err)
	}

	// Publish until both lanes have delivered (memory bus only delivers to live
	// subscribers, so retry while the goroutines register).
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = b.Publish(ctx, base, []byte("k"), []byte("shared"))
		_ = b.Publish(ctx, acmeTopic, []byte("k"), []byte("siloed"))
		mu.Lock()
		_, haveShared := got["shared"]
		_, haveSiloed := got["siloed"]
		mu.Unlock()
		if haveShared && haveSiloed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lanes did not both deliver: got=%v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if got["shared"] != "" {
		t.Fatalf("shared lane should carry empty laneTenant, got %q", got["shared"])
	}
	if got["siloed"] != "tenant-acme" {
		t.Fatalf("siloed lane should carry its authoritative tenant, got %q", got["siloed"])
	}
}
