// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/store"
)

// Agent-enrollment operator CLI (Sprint 11, ADR docs/adr/agent-enrollment.md;
// founder decision: admin API + CLI both mint through the same service path).

// runAgentCAInit generates the agent CA hierarchy ONCE and prints the ROOT key
// for offline custody — it is never persisted (ADR decision 2).
func runAgentCAInit(ctx context.Context, db *store.DB) error {
	rootKey, err := enroll.InitCA(ctx, db.Pool())
	if err != nil {
		return err
	}
	fmt.Println("agent CA initialized: root (10y) -> issuing intermediate (1y, sealed at rest)")
	fmt.Println()
	fmt.Println("ROOT CA PRIVATE KEY — shown ONCE, never stored. Move it to offline custody")
	fmt.Println("(HSM, sealed envelope, offline vault). It is needed only to issue a future")
	fmt.Println("intermediate; runtime operation does not use it.")
	fmt.Println()
	os.Stdout.Write(rootKey)
	return nil
}

// runAgentCAExport writes the agent CA trust bundle (root + intermediate
// PUBLIC certificates — never the sealed key) to a file, so an operator can
// point the control plane's PROBECTL_AGENT_TLS_CA_FILE at the pool that
// verifies enrolling agents. "-" writes to stdout. It needs no envelope key
// (public material only), so it works anywhere the database is reachable.
func runAgentCAExport(ctx context.Context, db *store.DB, args []string) error {
	if len(args) < 1 || args[0] == "" {
		return fmt.Errorf(`usage: probectl-control agent-ca export <file>   ("-" for stdout)`)
	}
	bundle, err := enroll.PublicBundle(ctx, db.Pool())
	if err != nil {
		return err
	}
	if args[0] == "-" {
		_, err := os.Stdout.Write(bundle)
		return err
	}
	if err := os.WriteFile(args[0], bundle, 0o644); err != nil {
		return fmt.Errorf("write agent CA bundle: %w", err)
	}
	fmt.Printf("agent CA trust bundle (root + intermediate) written to %s\n", args[0])
	fmt.Println("point the control plane's PROBECTL_AGENT_TLS_CA_FILE at this file so it verifies enrolling agents.")
	return nil
}

// runEnrollToken mints a one-time, tenant-scoped join token and prints it
// once, plus the server-certificate pin agents can use on first contact.
func runEnrollToken(ctx context.Context, cfg *config.Config, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant UUID the token is scoped to (REQUIRED — the token names the tenant)")
	agentID := fs.String("agent", "", "optionally pin the enrolling agent's id")
	name := fs.String("name", "", "operator label for the token")
	ttl := fs.Duration("ttl", enroll.DefaultTokenTTL, "token validity window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" {
		return fmt.Errorf("-tenant is required (the token, not the agent, names the tenant)")
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		return err
	}
	display, id, err := svc.MintToken(ctx, *tenant, *agentID, *name, "cli", *ttl)
	if err != nil {
		return err
	}
	fmt.Println("enrollment token (shown ONCE; single-use; expires", time.Now().Add(*ttl).UTC().Format(time.RFC3339)+"):")
	fmt.Println()
	fmt.Println("  " + display)
	fmt.Println()
	fmt.Println("token id (for revocation):", id)
	if pin := serverCertPin(cfg.TLSCertFile); pin != "" {
		fmt.Println("server cert pin (give the agent --ca-pin for first contact):", pin)
	}
	fmt.Println()
	fmt.Println("on the agent host:")
	fmt.Println("  probectl-agent enroll --server https://<control-host>:8443 --token <token> --dir /var/lib/probectl-agent/identity")
	return nil
}

// serverCertPin is the sha256 of the serving certificate (DER), hex — the
// first-contact pin printed alongside minted tokens (ADR decision 3).
func serverCertPin(certFile string) string {
	if certFile == "" {
		return ""
	}
	b, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(crypto.Hash(cert.Raw))
}

// runRevokeAgent persists an agent revocation from the CLI (Sprint 12,
// WIRE-003): the running control plane's periodic deny-list refresh (30s)
// picks it up; enrollment/rotation refuse the id immediately.
func runRevokeAgent(ctx context.Context, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("revoke-agent", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant UUID the agent belongs to (REQUIRED)")
	agent := fs.String("agent", "", "agent id to revoke (REQUIRED)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || *agent == "" {
		return fmt.Errorf("usage: probectl-control revoke-agent -tenant <uuid> -agent <id>")
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		return err
	}
	serials, spiffeID, err := svc.Revoke(ctx, *tenant, *agent, "cli")
	if err != nil {
		return err
	}
	fmt.Printf("revoked %s (%s): %d live serial(s) denied; a running control plane refuses its handshakes within 30s; re-enrollment/rotation refused immediately\n",
		*agent, spiffeID, len(serials))
	return nil
}

// runRevokeEnrollToken cancels an UNREDEEMED join token early — the
// "kill that invitation" button. The id is the value `enroll-token` printed
// at mint time. A token that was already redeemed is immutable history (the
// agent exists now — revoking the AGENT is `revoke-agent`'s job); this
// command only voids invitations that nobody has used yet.
func runRevokeEnrollToken(ctx context.Context, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("revoke-enroll-token", flag.ContinueOnError)
	id := fs.String("id", "", "token id to void (printed by enroll-token; REQUIRED)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("usage: probectl-control revoke-enroll-token -id <token-id>")
	}
	revoked, err := store.NewEnrollTokens(db.Pool()).Revoke(ctx, *id)
	if err != nil {
		return err
	}
	if !revoked {
		return fmt.Errorf("no unredeemed token with id %s — it was already redeemed, already revoked, or never existed; nothing changed (a redeemed token's agent is revoked with revoke-agent)", *id)
	}
	fmt.Printf("voided enroll token %s: it can no longer be redeemed (it was single-use and expiring anyway — this just ends it early)\n", *id)
	return nil
}
