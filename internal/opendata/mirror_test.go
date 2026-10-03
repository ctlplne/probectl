// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A file:// mirror lets threat-intel feeds load fully offline: the feed is read
// from the local filesystem and the network client is NEVER touched (air-gap —
// docs/guardrails.md G7-2). RTP-14.
func TestIntelFeedsLoadFromFileMirrorWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	// Operator mirrors each feed to a file named by the feed's source name.
	if err := os.WriteFile(filepath.Join(dir, "feodo_tracker"), []byte("# air-gap mirror\n192.0.2.66\n203.0.113.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A net Doer that MUST NOT be reached: any outbound fetch fails the test.
	blocked := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		t.Errorf("air-gap violated: outbound fetch to %s", req.URL)
		return nil, errors.New("blocked: no network in air-gap test")
	}}

	feeds := NewIntelFeeds([]string{"feodo_tracker"}, blocked, NewMirror("file://"+dir))
	if len(feeds) != 1 {
		t.Fatalf("built %d feeds, want 1", len(feeds))
	}

	store := NewIOCStore()
	r := NewIntelRefresher(store, feeds, time.Hour, discardLogger())
	if n := r.Refresh(context.Background()); n != 2 {
		t.Fatalf("loaded %d IOCs from the file mirror, want 2", n)
	}
	if m := store.ScoreIP("192.0.2.66"); len(m) != 1 || m[0].Source != "feodo_tracker" {
		t.Fatalf("mirrored IOC not matchable: %+v", m)
	}
	if blocked.calls != 0 {
		t.Fatalf("air-gap violated: %d outbound call(s) made", blocked.calls)
	}
}

func TestMirrorResolveAndClient(t *testing.T) {
	// Disabled mirror: canonical URL + the net client are returned unchanged.
	off := Mirror{}
	if off.Enabled() {
		t.Fatal("zero-value Mirror must be disabled")
	}
	if got := off.Resolve("spamhaus_drop", urlSpamhausDROP); got != urlSpamhausDROP {
		t.Fatalf("disabled Resolve = %q, want canonical", got)
	}
	if off.Client(nil) != nil {
		t.Fatal("disabled Client(nil) must stay nil so the caller defaults")
	}

	// A bare absolute path is normalised to a file:// URL and each source is
	// mirrored at <base>/<source>.
	m := NewMirror("/srv/mirror/")
	if got := m.Resolve("feodo_tracker", urlFeodo); got != "file:///srv/mirror/feodo_tracker" {
		t.Fatalf("Resolve = %q", got)
	}
	// An operator-hosted https base is kept as-is.
	h := NewMirror("https://mirror.internal/feeds")
	if got := h.Resolve("urlhaus", urlURLhaus); got != "https://mirror.internal/feeds/urlhaus" {
		t.Fatalf("https Resolve = %q", got)
	}
}
