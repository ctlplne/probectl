// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/store"
)

// Agent-enrollment operator CLI (Sprint 11, ADR docs/adr/agent-enrollment.md;
// founder decision: admin API + CLI both mint through the same service path).

// runAgentCAInit generates the agent CA hierarchy ONCE and prints the ROOT key
// for offline custody — it is never persisted (ADR decision 2).
func runAgentCAInit(ctx context.Context, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("agent-ca init", flag.ContinueOnError)
	keyOut := fs.String("key-out", "", "write the root private key to this file (0600) instead of stdout")
	printKey := fs.Bool("print-key", false, "print the root private key to stdout even when stdout is not a terminal (it will be stored wherever that output goes)")
	ifMissing := fs.Bool("if-missing", false, "succeed and change nothing when the agent CA already exists (for repeatable bootstrap one-shots)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// DPR-136: refusing to overwrite the trust root is right, but a bootstrap
	// one-shot that has to run exactly once is not repeatable — a second
	// `compose up`, a re-applied Job or a re-run pipeline step fails on a
	// deployment that is already correct, and takes everything downstream of it
	// with it. The refusal stays the default; -if-missing is the `certgen
	// --if-missing` idiom for the automated caller, and it never overwrites.
	if *ifMissing {
		if initialized, err := enroll.CAInitialized(ctx, db.Pool()); err != nil {
			return err
		} else if initialized {
			fmt.Println("agent CA already initialized — left untouched (-if-missing)")
			return nil
		}
	}
	// DPR-121: "shown once, never stored" is true of the DATABASE, and it used
	// to depend entirely on how the command was run. Through `kubectl exec` the
	// key reaches the operator's terminal; through a Job, a Helm hook or a CI
	// step — the ordinary way to automate a bootstrap — the same bytes land in
	// the cluster's log store, readable by anyone with pods/log, with nothing
	// said about it. Writing a root CA private key to a log is exactly what
	// guardrail 6 forbids, so a non-terminal stdout now has to be asked for.
	if *keyOut == "" && !*printKey && !isTerminal(os.Stdout) {
		return errors.New("refusing to print the root CA private key to a non-terminal: it would be stored " +
			"wherever that output goes (a Job's pod log, a CI artifact, a shell redirect). " +
			"Use -key-out <file> to write it 0600 for offline custody, or -print-key if the destination " +
			"really is safe custody (a pipe into your vault)")
	}
	rootKey, err := enroll.InitCA(ctx, db.Pool())
	if err != nil {
		return err
	}
	fmt.Println("agent CA initialized: root (10y) -> issuing intermediate (1y, sealed at rest)")
	fmt.Println()
	if *keyOut != "" {
		if err := os.WriteFile(*keyOut, rootKey, 0o600); err != nil {
			return fmt.Errorf("write root key: %w", err)
		}
		fmt.Printf("ROOT CA PRIVATE KEY written to %s (0600) — never stored anywhere else.\n", *keyOut)
		fmt.Println("Move it to offline custody (HSM, sealed envelope, offline vault) and delete the file.")
		fmt.Println("It is needed only to issue a future intermediate; runtime operation does not use it.")
		return nil
	}
	fmt.Println("ROOT CA PRIVATE KEY — shown ONCE, never stored. Move it to offline custody")
	fmt.Println("(HSM, sealed envelope, offline vault). It is needed only to issue a future")
	fmt.Println("intermediate; runtime operation does not use it.")
	fmt.Println()
	os.Stdout.Write(rootKey)
	return nil
}

// isTerminal reports whether f is a character device — an interactive terminal
// rather than a pipe, a file or a container log.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
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

// runRegisterCollector registers a bus-publishing collector or BMP router
// from a one-time enroll token and prints the minted UUID identity for it to
// stamp on its records (ARCH-011). Bus collectors authenticate to the broker;
// plane=bmp additionally signs the router-owned CSR and records the resulting
// SVID in the same authoritative identity registry.
func runRegisterCollector(ctx context.Context, cfg *config.Config, db *store.DB, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("register-collector", flag.ContinueOnError)
	token := fs.String("token", "", "one-time enroll token (pjt_...; REQUIRED)")
	plane := fs.String("plane", "", "collector plane: bgp | bmp | ebpf | flow | device | endpoint (REQUIRED)")
	hostname := fs.String("hostname", "", "operator label / source host")
	csrFile := fs.String("csr", "", "BMP router CSR PEM file (required for plane=bmp)")
	certOut := fs.String("cert-out", "", "write issued BMP leaf+intermediate chain here")
	caOut := fs.String("ca-out", "", "write BMP trust bundle here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *plane == "" {
		return fmt.Errorf("-token and -plane are required (mint a token with enroll-token)")
	}
	var csrPEM string
	if *plane == "bmp" {
		if *csrFile == "" || *certOut == "" || *caOut == "" {
			return fmt.Errorf("plane=bmp requires -csr, -cert-out, and -ca-out")
		}
		raw, err := os.ReadFile(*csrFile)
		if err != nil {
			return fmt.Errorf("read BMP router CSR: %w", err)
		}
		csrPEM = string(raw)
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		return err
	}
	// DPR-081: the control-host CLI registers through the same quota seam as
	// the API; a licensed metering deployment refuses a collector past the
	// tenant's agent cap here too.
	if lic, lerr := control.BuildLicense(cfg, log); lerr == nil {
		attachQuotaChecker(lic, db.Pool())
	} else {
		log.Warn("register-collector: license unavailable, quota not enforced", "error", lerr.Error())
	}
	id, err := svc.RegisterCollector(ctx, *token, *hostname, *plane, csrPEM)
	if err != nil {
		return err
	}
	fmt.Println("collector registered. Configure the collector with:")
	fmt.Println("  tenant_id:", id.TenantID)
	fmt.Println("  agent_id: ", id.AgentID)
	fmt.Println("  plane:    ", id.Plane)
	// DPR-049: agent-published planes publish on the tenant's namespaced lane.
	if ns, nerr := store.NewTenants(db.Pool()).BusNamespace(ctx, id.TenantID); nerr == nil {
		if env := collectorLaneEnv(id.Plane); env != "" {
			fmt.Println("  bus: {namespace: " + ns + "}   (" + env + "; required in the multi-tenant/regulated profiles, where the shared lane is refused)")
		}
	}
	if id.SVID != nil {
		if err := os.WriteFile(*certOut, []byte(id.SVID.CertPEM), 0o600); err != nil {
			return fmt.Errorf("write BMP certificate: %w", err)
		}
		if err := os.WriteFile(*caOut, []byte(id.SVID.CABundle), 0o644); err != nil {
			return fmt.Errorf("write BMP trust bundle: %w", err)
		}
		fmt.Println("  spiffe_id:", id.SVID.SPIFFEID)
		fmt.Println("  serial:   ", id.SVID.Serial)
		fmt.Println("  cert:     ", *certOut)
		fmt.Println("  ca_bundle:", *caOut)
	}
	fmt.Println()
	if id.Plane == "bmp" {
		fmt.Println("install the issued certificate with the CSR's existing private key on the BMP router;")
		fmt.Println("the listener admits only this exact registry-issued tenant/plane/serial identity.")
	} else {
		fmt.Println("stamp agent_id on every record the collector publishes to the bus;")
		fmt.Println("the control plane verifies it against this registry row (TENANT-101).")
	}
	return nil
}

// serverCertPin is the sha256 of the serving certificate (DER), hex — the
// first-contact pin printed alongside minted tokens (ADR decision 3).
func serverCertPin(certFile string) string {
	if certFile == "" {
		return ""
	}
	pin, err := crypto.CertificatePinFile(certFile)
	if err != nil {
		return ""
	}
	return pin
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

// collectorLaneEnv names the collector's bus-namespace setting for its plane
// (DPR-049); BGP/BMP publish through the listener and analyzer instead.
func collectorLaneEnv(plane string) string {
	switch plane {
	case "flow":
		return "PROBECTL_FLOW_BUS_NAMESPACE"
	case "device":
		return "PROBECTL_DEVICE_BUS_NAMESPACE"
	case "endpoint":
		return "PROBECTL_ENDPOINT_BUS_NAMESPACE"
	case "ebpf":
		return "PROBECTL_EBPF_BUS_NAMESPACE"
	}
	return ""
}
