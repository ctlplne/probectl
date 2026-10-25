// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
)

// rotationStack is a control plane for the rotation tests: the agent gRPC
// listener (client CA = the collector CA) with a fake L7 policy, and an HTTPS
// /enroll/agent/rotate that, like the enrollment service, requires proof of
// the current key and re-issues the SAME eBPF identity.
type rotationStack struct {
	dir, grpcAddr, rotateURL, caFile string
	ca                               *crypto.CA
	policy                           *channelPolicy
	mu                               sync.Mutex
	rotations                        int
	leafTTL                          time.Duration
}

func startRotationStack(t *testing.T, leafTTL time.Duration) *rotationStack {
	t.Helper()
	st := &rotationStack{dir: t.TempDir(), leafTTL: leafTTL, policy: &channelPolicy{floor: "metadata"}}
	ca, err := crypto.GenerateCA("d43-r2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st.ca = ca
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st.caFile = writeChannelFile(t, st.dir, "server-ca.pem", ca.CertPEM())
	srv, err := agenttransport.New(writeChannelFile(t, st.dir, "srv.pem", sc), writeChannelFile(t, st.dir, "srv.key", sk), st.caFile,
		nil, bus.NewMemory(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.WithL7Policy(st.policy)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.ServeListener(ctx, ln); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	st.grpcAddr = ln.Addr().String()

	pair, err := tls.X509KeyPair(sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(http.HandlerFunc(st.serveRotate))
	hs.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	hs.StartTLS()
	t.Cleanup(hs.Close)
	st.rotateURL = hs.URL
	return st
}

func (st *rotationStack) serveRotate(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/enroll/agent/rotate" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var in struct{ CertPEM, CSRPEM, Proof string }
	raw, _ := io.ReadAll(r.Body)
	var m map[string]string
	if json.Unmarshal(raw, &m) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	in.CertPEM, in.CSRPEM, in.Proof = m["cert_pem"], m["csr_pem"], m["proof"]
	cur, err := firstLeaf([]byte(in.CertPEM))
	if err != nil || time.Now().After(cur.NotAfter) {
		http.Error(w, "not ours", http.StatusUnauthorized)
		return
	}
	proof, _ := hex.DecodeString(in.Proof)
	if crypto.ECDSAVerifyCert(cur, []byte(in.CSRPEM), proof) != nil {
		http.Error(w, "bad proof", http.StatusUnauthorized)
		return
	}
	id, err := crypto.EBPFSPIFFEIDFromCert(cur)
	if err != nil {
		http.Error(w, "not ours", http.StatusUnauthorized)
		return
	}
	st.mu.Lock()
	ttl := st.leafTTL
	st.mu.Unlock()
	leaf, _, err := st.ca.SignCSR([]byte(in.CSRPEM), id.String(), ttl)
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	nl, _ := firstLeaf(leaf)
	st.mu.Lock()
	st.rotations++
	st.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"cert_pem": string(leaf), "ca_bundle": string(st.ca.CertPEM()),
		"spiffe_id": id.String(), "not_after": nl.NotAfter})
}

// issue writes a fresh eBPF-plane identity for agentID into dir.
func (st *rotationStack) issue(t *testing.T, dir, agentID string) (certFile, keyFile string) {
	t.Helper()
	csr, key, err := crypto.CreateCSR("ebpf-node")
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	ttl := st.leafTTL
	st.mu.Unlock()
	cert, _, err := st.ca.SignCSR(csr, crypto.EBPFSPIFFEID(d43Tenant, agentID), ttl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return writeChannelFile(t, dir, "cert.pem", cert), writeChannelFile(t, dir, "key.pem", key)
}

func (st *rotationStack) config(agentID, certFile, keyFile, seed string) *Config {
	cfg := consentedConfig()
	cfg.AgentID = agentID
	cfg.FixturePath = "testdata/flows.json"
	cfg.ControlPlane = ControlPlaneConfig{GRPCAddr: st.grpcAddr, ServerName: "localhost", CertFile: certFile, KeyFile: keyFile,
		CAFile: st.caFile, RotateURL: st.rotateURL, IdentitySeedDir: seed}
	return cfg
}

const r2Agent = "77777777-7777-4777-8777-777777777777"

// D-43 R2: the policy channel's certificate is renewed at two thirds of its
// lifetime — before it expires — through the rotation endpoint, keeping the
// same eBPF identity, and the running agent's channel keeps working.
func TestEBPFCertRotatesBeforeExpiry(t *testing.T) {
	st := startRotationStack(t, time.Hour)
	certFile, keyFile := st.issue(t, filepath.Join(st.dir, "identity"), r2Agent)
	_ = recordLiveStarts(t)
	a, err := New(st.config(r2Agent, certFile, keyFile, ""), bus.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if a.rotator == nil {
		t.Fatal("an agent with a policy channel has no certificate rotator")
	}
	old, _ := readLeaf(certFile)
	life := old.NotAfter.Sub(old.NotBefore)

	a.rotator.now = func() time.Time { return old.NotBefore.Add(life / 2) }
	if rotated, err := a.rotator.check(context.Background()); err != nil || rotated {
		t.Fatalf("rotated at half its lifetime: %v %v", rotated, err)
	}
	at := old.NotBefore.Add(life * 7 / 10)
	a.rotator.now = func() time.Time { return at }
	if rotated, err := a.rotator.check(context.Background()); err != nil || !rotated {
		t.Fatalf("did not rotate at 70%% of its lifetime: %v %v", rotated, err)
	}
	if !at.Before(old.NotAfter) {
		t.Fatal("the rotation point is not before expiry")
	}
	renewed, _ := readLeaf(certFile)
	oldID, _ := crypto.EBPFSPIFFEIDFromCert(old)
	newID, _ := crypto.EBPFSPIFFEIDFromCert(renewed)
	if renewed.SerialNumber.Cmp(old.SerialNumber) == 0 || newID != oldID || renewed.NotAfter.Before(old.NotAfter) {
		t.Fatalf("rotation did not renew the same identity: old %s %v, new %s %v", old.SerialNumber, oldID, renewed.SerialNumber, newID)
	}
	// The running agent's channel still answers (a new handshake presents the
	// renewed certificate).
	if floor, err := fetchFloor(context.Background(), a.policy); err != nil || floor != "metadata" {
		t.Fatalf("channel after rotation: %q %v", floor, err)
	}
}

// A restart after rotation keeps consented capture working — even once the
// registration's original certificate has expired — because the agent uses
// the rotated identity and the seed never overwrites a newer one. The
// original certificate alone is refused (the negative control).
func TestEBPFRestartAfterRotationKeepsCapture(t *testing.T) {
	st := startRotationStack(t, 3*time.Second)
	seed := filepath.Join(st.dir, "seed")
	seedCert, seedKey := st.issue(t, seed, r2Agent)
	live := filepath.Join(st.dir, "identity")
	certFile, keyFile := filepath.Join(live, "cert.pem"), filepath.Join(live, "key.pem")
	_ = recordLiveStarts(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	a, err := New(st.config(r2Agent, certFile, keyFile, seed), bus.NewMemory(), log)
	if err != nil {
		t.Fatal(err)
	}
	if !a.L7CaptureActive() {
		t.Fatal("the seeded agent did not start consented capture")
	}
	// The registration's certificate lives 3 s; renewals get the normal TTL.
	st.mu.Lock()
	st.leafTTL = time.Hour
	st.mu.Unlock()
	a.rotator.now = func() time.Time { return time.Now().Add(2500 * time.Millisecond) } // past 2/3 of 3 s
	if rotated, err := a.rotator.check(context.Background()); err != nil || !rotated {
		t.Fatalf("rotation: %v %v", rotated, err)
	}
	orig, _ := readLeaf(seedCert)
	time.Sleep(time.Until(orig.NotAfter) + 1200*time.Millisecond) // the registration's certificate has now expired
	if time.Now().Before(orig.NotAfter) {
		t.Fatal("the original certificate has not expired yet")
	}

	rec := recordLiveStarts(t)
	restarted, err := New(st.config(r2Agent, certFile, keyFile, seed), bus.NewMemory(), log)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.starts) != 1 || !restarted.L7CaptureActive() || restarted.L7CaptureChannelRefused() {
		t.Fatalf("restart after rotation lost consented capture: starts=%v channel_refused=%v", rec.starts, restarted.L7CaptureChannelRefused())
	}
	if cur, _ := readLeaf(certFile); cur.SerialNumber.Cmp(orig.SerialNumber) == 0 {
		t.Fatal("the seed overwrote the rotated certificate")
	}

	// Negative control: the registration's expired certificate alone is refused.
	neg := recordLiveStarts(t)
	refused, err := New(st.config(r2Agent, seedCert, seedKey, ""), bus.NewMemory(), log)
	if err != nil {
		t.Fatal(err)
	}
	if len(neg.starts) != 0 || refused.L7CaptureActive() {
		t.Fatal("an expired certificate still started capture")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rotations != 1 {
		t.Fatalf("rotation endpoint called %d times", st.rotations)
	}
}

func TestSeedIdentityNeverOverwritesANewerCertificate(t *testing.T) {
	st := startRotationStack(t, time.Hour)
	seed := filepath.Join(st.dir, "seed")
	st.issue(t, seed, r2Agent)
	live := filepath.Join(st.dir, "live")
	cert, key := filepath.Join(live, "cert.pem"), filepath.Join(live, "key.pem")
	if seeded, err := seedIdentity(seed, cert, key); err != nil || !seeded {
		t.Fatalf("empty identity dir not seeded: %v %v", seeded, err)
	}
	st.leafTTL = 2 * time.Hour
	st.issue(t, live, r2Agent) // a newer (rotated) certificate in place
	if seeded, _ := seedIdentity(seed, cert, key); seeded {
		t.Fatal("the older seed overwrote a newer certificate")
	}
	st.leafTTL = 3 * time.Hour
	st.issue(t, seed, r2Agent) // a fresh registration
	if seeded, _ := seedIdentity(seed, cert, key); !seeded {
		t.Fatal("a fresh registration was not applied")
	}
	// A longer-lived certificate of ANOTHER identity in the state directory
	// (a re-registration under a new agent id) never shadows the seed.
	st.leafTTL = 9 * time.Hour
	st.issue(t, live, "88888888-8888-4888-8888-888888888888")
	if seeded, _ := seedIdentity(seed, cert, key); !seeded {
		t.Fatal("a certificate of another identity shadowed the seed")
	}
	if cur, _ := readLeaf(cert); !strings.Contains(cur.URIs[0].String(), r2Agent) {
		t.Fatalf("identity after seeding = %v", cur.URIs)
	}
}
