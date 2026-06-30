// SPDX-License-Identifier: LicenseRef-probectl-TBD

package change

import (
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func hmacHeader(secret string, body []byte) string {
	return "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), body))
}

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// --- normalization across source types ---

func TestGenericNormalize(t *testing.T) {
	p := genericProvider{}
	// single object
	one := []byte(`{"kind":"deploy","title":"deploy api","target":"api.example.com","actor":"ci","ref":"abc123"}`)
	evs, err := p.Normalize(one, nil, t0)
	if err != nil || len(evs) != 1 {
		t.Fatalf("single: %v %+v", err, evs)
	}
	if evs[0].Kind != KindDeploy || evs[0].Target != "api.example.com" || evs[0].Source != ProviderGeneric {
		t.Errorf("single event = %+v", evs[0])
	}
	// envelope with two; one malformed (no title) is dropped
	env := []byte(`{"events":[{"title":"a","target":"x"},{"target":"no-title"}]}`)
	if evs, err = p.Normalize(env, nil, t0); err != nil || len(evs) != 1 {
		t.Fatalf("envelope: %v %+v", err, evs)
	}
	// bare array
	arr := []byte(`[{"title":"b"},{"title":"c"}]`)
	if evs, err = p.Normalize(arr, nil, t0); err != nil || len(evs) != 2 {
		t.Fatalf("array: %v %+v", err, evs)
	}
	// occurred-at defaulted to now; kind defaulted to other
	if evs[0].OccurredAt != t0 || evs[0].Kind != KindOther {
		t.Errorf("defaults not applied: %+v", evs[0])
	}
	// junk → ErrNormalize
	if _, err := p.Normalize([]byte(`not json`), nil, t0); err == nil {
		t.Error("want ErrNormalize for junk body")
	}
}

func TestNormalizeClampsGrossFutureOccurredAt(t *testing.T) {
	p := genericProvider{}
	future := t0.Add(2 * time.Hour).Format(time.RFC3339Nano)
	body := []byte(`{"kind":"deploy","title":"future deploy","target":"api.example.com","occurred_at":"` + future + `"}`)
	evs, err := p.Normalize(body, nil, t0)
	if err != nil || len(evs) != 1 {
		t.Fatalf("normalize: %v %+v", err, evs)
	}
	if !evs[0].OccurredAt.Equal(t0) {
		t.Fatalf("gross future occurred_at should clamp to ingest time: got %s want %s", evs[0].OccurredAt, t0)
	}
	if evs[0].Attributes["occurred_at_clamped"] != "true" || evs[0].Attributes["original_occurred_at"] != future {
		t.Fatalf("clamp provenance missing: %+v", evs[0].Attributes)
	}
}

func TestGitHubNormalize(t *testing.T) {
	p := githubProvider{}
	push := []byte(`{"ref":"refs/heads/main","compare":"https://gh/compare","pusher":{"name":"alice"},
		"repository":{"full_name":"acme/shop"},"head_commit":{"id":"deadbeef","message":"fix checkout\nbody","url":"https://gh/c/deadbeef"},
		"commits":[{"id":"deadbeef"}]}`)
	evs, err := p.Normalize(push, hdr(githubEventHeader, "push"), t0)
	if err != nil || len(evs) != 1 {
		t.Fatalf("push: %v %+v", err, evs)
	}
	if evs[0].Kind != KindCommit || evs[0].Actor != "alice" || evs[0].Ref != "deadbeef" ||
		evs[0].Target != "acme/shop" || evs[0].Summary != "fix checkout" || evs[0].Attributes["branch"] != "main" {
		t.Errorf("github push = %+v", evs[0])
	}

	deploy := []byte(`{"deployment":{"environment":"production","sha":"cafe","environment_url":"https://api.example.com/","creator":{"login":"bob"}},
		"repository":{"full_name":"acme/api"}}`)
	if evs, err = p.Normalize(deploy, hdr(githubEventHeader, "deployment"), t0); err != nil || len(evs) != 1 {
		t.Fatalf("deploy: %v %+v", err, evs)
	}
	if evs[0].Kind != KindDeploy || evs[0].Target != "api.example.com" || evs[0].Attributes["environment"] != "production" {
		t.Errorf("github deploy = %+v", evs[0])
	}

	// ping (verified handshake) and unmodeled events → zero events, no error
	if evs, err := p.Normalize([]byte(`{"zen":"hi"}`), hdr(githubEventHeader, "ping"), t0); err != nil || len(evs) != 0 {
		t.Errorf("ping should yield no events: %v %+v", err, evs)
	}
}

func TestGitLabNormalize(t *testing.T) {
	p := gitlabProvider{}
	push := []byte(`{"ref":"refs/heads/main","user_name":"carol","checkout_sha":"99aa",
		"project":{"path_with_namespace":"team/svc","web_url":"https://gl/team/svc"},
		"commits":[{"message":"bump","url":"https://gl/c/99aa"}]}`)
	evs, err := p.Normalize(push, hdr(gitlabEventHeader, "Push Hook"), t0)
	if err != nil || len(evs) != 1 || evs[0].Kind != KindCommit || evs[0].Target != "team/svc" || evs[0].Actor != "carol" {
		t.Fatalf("gitlab push = %v %+v", err, evs)
	}

	deploy := []byte(`{"environment":"prod","deployable_url":"https://svc.example.net/app","short_sha":"99aa",
		"status":"success","user":{"name":"carol"},"project":{"path_with_namespace":"team/svc"}}`)
	if evs, err = p.Normalize(deploy, hdr(gitlabEventHeader, "Deployment Hook"), t0); err != nil || len(evs) != 1 {
		t.Fatalf("gitlab deploy: %v %+v", err, evs)
	}
	if evs[0].Kind != KindDeploy || evs[0].Target != "svc.example.net" || evs[0].Attributes["status"] != "success" {
		t.Errorf("gitlab deploy = %+v", evs[0])
	}
}

// --- signature / token verification (unsigned + forged rejected) ---

func TestVerify(t *testing.T) {
	body := []byte(`{"title":"x"}`)
	secret := "s3cr3t"

	// generic HMAC
	g := genericProvider{}
	if !g.Verify(secret, body, hdr(GenericSignatureHeader, hmacHeader(secret, body))) {
		t.Error("generic: valid HMAC should verify")
	}
	if g.Verify(secret, body, nil) {
		t.Error("generic: unsigned must be rejected")
	}
	if g.Verify(secret, body, hdr(GenericSignatureHeader, hmacHeader("wrong", body))) {
		t.Error("generic: forged HMAC must be rejected")
	}
	if g.Verify(secret, []byte(`{"title":"tampered"}`), hdr(GenericSignatureHeader, hmacHeader(secret, body))) {
		t.Error("generic: tampered body must be rejected")
	}

	// github HMAC
	gh := githubProvider{}
	if !gh.Verify(secret, body, hdr(GitHubSignatureHeader, hmacHeader(secret, body))) {
		t.Error("github: valid signature should verify")
	}
	if gh.Verify(secret, body, hdr(GitHubSignatureHeader, "sha256=00")) {
		t.Error("github: forged signature must be rejected")
	}

	// gitlab shared token (constant-time compare)
	gl := gitlabProvider{}
	if !gl.Verify(secret, body, hdr(GitLabTokenHeader, secret)) {
		t.Error("gitlab: matching token should verify")
	}
	if gl.Verify(secret, body, hdr(GitLabTokenHeader, "nope")) {
		t.Error("gitlab: wrong token must be rejected")
	}
	if gl.Verify(secret, body, nil) {
		t.Error("gitlab: missing token must be rejected")
	}
}

func TestProviderRegistry(t *testing.T) {
	for _, n := range ProviderNames() {
		if _, ok := ProviderByName(n); !ok {
			t.Errorf("provider %q not resolvable", n)
		}
	}
	if _, ok := ProviderByName("bogus"); ok {
		t.Error("bogus provider should be unknown")
	}
}

// --- correlation ---

func TestCandidates(t *testing.T) {
	at := t0
	changes := []Event{
		{Title: "deploy api", Target: "api.example.com", OccurredAt: at.Add(-2 * time.Minute)}, // exact target, recent
		{Title: "deploy db", Target: "db.example.com", OccurredAt: at.Add(-3 * time.Minute)},   // different target
		{Title: "route change", Prefix: "192.0.2.0/24", OccurredAt: at.Add(-10 * time.Minute)}, // prefix contains incident IP
		{Title: "old deploy", Target: "api.example.com", OccurredAt: at.Add(-48 * time.Hour)},  // out of window
	}

	// incident on a specific host inside 192.0.2.0/24
	cands := Candidates(changes, "api.example.com", "", at, time.Hour)
	if len(cands) != 1 || cands[0].Event.Title != "deploy api" {
		t.Fatalf("host-target correlation = %+v", cands)
	}

	// incident keyed on an IP in the prefix → the route change correlates
	cands = Candidates(changes, "192.0.2.10", "", at, time.Hour)
	titles := map[string]bool{}
	for _, c := range cands {
		titles[c.Event.Title] = true
	}
	if !titles["route change"] {
		t.Errorf("IP-in-prefix change should correlate: %+v", cands)
	}
	if titles["deploy db"] {
		t.Errorf("unrelated target must be dropped: %+v", cands)
	}

	// no incident target → recent changes ranked by recency (out-of-window still dropped)
	cands = Candidates(changes, "", "", at, time.Hour)
	if len(cands) != 3 {
		t.Fatalf("untargeted should keep 3 in-window changes, got %d: %+v", len(cands), cands)
	}
	if !cands[0].Event.OccurredAt.After(cands[1].Event.OccurredAt) {
		t.Errorf("untargeted candidates should be newest-first: %+v", cands)
	}
}

func hdr(k, v string) http.Header {
	h := http.Header{}
	h.Set(k, v)
	return h
}
