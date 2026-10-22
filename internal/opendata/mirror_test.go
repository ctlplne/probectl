// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"io"
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

// A file:// mirror serves only files inside its configured directory (CodeQL
// #37). The request path comes from an outgoing request URL; one that resolves
// outside the mirror, by ".." or by naming another location on the host, must
// be refused before anything is opened, while every feed file inside the
// mirror still serves and the network client is never reached.
func TestFileMirrorRefusesPathsOutsideItsDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "mirror")
	for path, body := range map[string]string{
		filepath.Join(root, "feodo_tracker"):  "192.0.2.66\n",
		filepath.Join(root, "outage", "ioda"): "{}",
		filepath.Join(parent, "secret"):       "outside the mirror\n",
		// A sibling whose name starts with the mirror's is still outside it.
		filepath.Join(root+"-evil", "feodo_tracker"): "203.0.113.9\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blocked := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		t.Errorf("file request reached the network client: %s", req.URL)
		return nil, errors.New("blocked: no network in this test")
	}}
	mirror := NewMirror("file://" + root).Client(blocked)

	for _, tc := range []struct {
		name string
		url  string
		want string // the served body; "" = must be refused
	}{
		{name: "feed in the mirror", url: "file://" + root + "/feodo_tracker?since=0", want: "192.0.2.66\n"},
		{name: "nested feed", url: "file://" + root + "/outage/ioda", want: "{}"},
		{name: "dot segments that stay inside", url: "file://" + root + "/outage/../feodo_tracker", want: "192.0.2.66\n"},
		{name: "dot-dot escape", url: "file://" + root + "/../secret"},
		{name: "encoded dot-dot escape", url: "file://" + root + "/%2e%2e/secret"},
		{name: "deep escape", url: "file://" + root + "/outage/../../secret"},
		{name: "absolute path elsewhere", url: "file://" + filepath.Join(parent, "secret")},
		{name: "sibling sharing the prefix", url: "file://" + root + "-evil/feodo_tracker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := mirror.Do(req)
			if tc.want == "" {
				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					t.Fatalf("%s served %q from outside the mirror", tc.url, body)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s refused inside the mirror: %v", tc.url, err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || string(body) != tc.want {
				t.Fatalf("%s served %q (%v), want %q", tc.url, body, err, tc.want)
			}
		})
	}

	// An https mirror has no local directory, so a file:// request is refused.
	https := NewMirror("https://mirror.internal/feeds").Client(blocked)
	req, err := http.NewRequest(http.MethodGet, "file://"+root+"/feodo_tracker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := https.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an https mirror served a local file")
	}
	if blocked.calls != 0 {
		t.Fatalf("%d file request(s) reached the network client", blocked.calls)
	}
}
