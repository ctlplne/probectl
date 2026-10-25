// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package ebpf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func rotationDSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
}

// D-43 R2 on the real stack: an eBPF collector registered by the enrollment
// service with a CSR renews its eBPF-plane SVID through the real
// enrollment service's /enroll/agent/rotate, keeps the same identity, and can
// rotate again from the renewed certificate (its serial is on record).
func TestEBPFCollectorRotatesAgainstTheRealEnrollmentService(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, rotationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
		return
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	sealer, err := tenantcrypto.NewEnvelopeSealer("test", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	if _, err := enroll.InitCA(ctx, db.Pool()); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init CA: %v", err)
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("ebpf-rotate-%d", time.Now().UnixNano()), "ebpf-rotate")
	if err != nil {
		t.Fatal(err)
	}
	srv := control.New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	token, _, err := svc.MintToken(ctx, tn.ID, "", "ebpf-node", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, key, err := crypto.CreateCSR("ebpf-node")
	if err != nil {
		t.Fatal(err)
	}
	// The registration the handler serves (/v1/collectors/register) — called
	// on the service here, since the dev principal exists only in control's
	// test binary; the rotation below goes through the real HTTP route.
	reg, err := svc.RegisterCollectorForTenant(ctx, tn.ID, token, "ebpf-node", "ebpf", string(csr))
	if err != nil || reg.SVID == nil {
		t.Fatalf("register: %v", err)
	}

	api := httptest.NewTLSServer(h)
	t.Cleanup(api.Close)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "api-ca.pem")
	for p, b := range map[string][]byte{certFile: []byte(reg.SVID.CertPEM), keyFile: key,
		caFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := newIdentityRotator(ControlPlaneConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, RotateURL: api.URL},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	want := crypto.EBPFSPIFFEID(tn.ID, reg.AgentID)
	prev, _ := readLeaf(certFile)
	for round := 1; round <= 2; round++ {
		life := prev.NotAfter.Sub(prev.NotBefore)
		r.now = func() time.Time { return prev.NotBefore.Add(life * 7 / 10) }
		if rotated, err := r.check(ctx); err != nil || !rotated {
			t.Fatalf("round %d: rotation against the real endpoint: %v %v", round, rotated, err)
		}
		cur, _ := readLeaf(certFile)
		id, err := crypto.EBPFSPIFFEIDFromCert(cur)
		if err != nil || id.String() != want || cur.SerialNumber.Cmp(prev.SerialNumber) == 0 {
			t.Fatalf("round %d: renewed %v (%v), want a new serial for %s", round, id, err, want)
		}
		prev = cur
	}
}
