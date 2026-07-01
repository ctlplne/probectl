// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-license is the issuer-side license tool (S-T0): generate
// signing keypairs, sign license files, and verify/inspect them. The private
// key is the founder's crown jewel — it lives OFFLINE, never in the repo,
// never on a server (CLAUDE.md §7 guardrail 6). Verification inside the
// product uses only the build-time-baked public keys.
//
// Usage:
//
//	probectl-license gen-key  -out-priv license-signing.key -out-pub license-signing.pub
//	probectl-license sign     -key license-signing.key -customer "Acme Corp" \
//	    -tier enterprise -expires 2027-06-30 [-features byok,...] [-tenant-band 25] \
//	    -out probectl-license.json
//	probectl-license verify   -file probectl-license.json -pub license-signing.pub
//	probectl-license inspect  -file probectl-license.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/license"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "gen-key":
		err = genKey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: probectl-license <gen-key|sign|verify|inspect> [flags]")
}

func genKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
	outPriv := fs.String("out-priv", "license-signing.key", "private key output path (KEEP OFFLINE)")
	outPub := fs.String("out-pub", "license-signing.pub", "public key output path (baked into release builds)")
	_ = fs.Parse(args)

	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPriv, priv, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*outPub, pub, 0o644); err != nil { //nolint:gosec // a public key is public
		return err
	}
	fmt.Printf("wrote %s (PRIVATE — keep offline, never commit) and %s\n", *outPriv, *outPub)
	fmt.Printf("bake into release builds with:\n  -ldflags \"-X github.com/imfeelingtheagi/probectl/internal/license.builtinPubKeysB64=%s\"\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "signing private key (PEM)")
	customer := fs.String("customer", "", "customer name")
	id := fs.String("id", "", "license id (default lic_<unix>)")
	tier := fs.String("tier", "", "enterprise | provider")
	features := fs.String("features", "", "comma-separated explicit extras (bespoke deals)")
	band := fs.Int("tenant-band", 0, "provider tenant band (0 = unlimited)")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD (UTC end of day)")
	out := fs.String("out", "probectl-license.json", "license file output path")
	_ = fs.Parse(args)

	if *keyPath == "" || *customer == "" || *tier == "" || *expires == "" {
		return fmt.Errorf("sign requires -key, -customer, -tier, -expires")
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	exp, err := time.Parse("2006-01-02", *expires)
	if err != nil {
		return fmt.Errorf("parse -expires: %w", err)
	}
	c := license.Claims{
		V:          1,
		ID:         *id,
		Customer:   *customer,
		Tier:       license.Tier(*tier),
		TenantBand: *band,
		IssuedAt:   time.Now().UTC().Truncate(time.Second),
		ExpiresAt:  exp.Add(24*time.Hour - time.Second).UTC(),
	}
	if c.ID == "" {
		c.ID = fmt.Sprintf("lic_%d", time.Now().Unix())
	}
	if *features != "" {
		for _, f := range strings.Split(*features, ",") {
			c.Features = append(c.Features, license.Feature(strings.TrimSpace(f)))
		}
	}
	raw, err := license.Sign(c, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s — %s · %s · expires %s\n", *out, c.Customer, c.Tier, c.ExpiresAt.Format(time.RFC3339))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	file := fs.String("file", "probectl-license.json", "license file")
	pub := fs.String("pub", "", "public key (PEM) to verify against")
	_ = fs.Parse(args)
	if *pub == "" {
		return fmt.Errorf("verify requires -pub")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	pubPEM, err := os.ReadFile(*pub)
	if err != nil {
		return err
	}
	c, err := license.Verify(raw, [][]byte{pubPEM})
	if err != nil {
		return err
	}
	fmt.Printf("VALID — %s · %s · expires %s\n", c.Customer, c.Tier, c.ExpiresAt.Format(time.RFC3339))
	return nil
}

func inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	file := fs.String("file", "probectl-license.json", "license file")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	// Inspect decodes WITHOUT verifying (it says so) — for reading a file's
	// claims when the public key isn't at hand.
	var f license.File
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("malformed license file: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return fmt.Errorf("malformed payload: %w", err)
	}
	var c license.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return fmt.Errorf("malformed claims: %w", err)
	}
	fmt.Printf("UNVERIFIED CLAIMS (run `verify` to check the signature):\n")
	fmt.Printf("  id:          %s\n  customer:    %s\n  tier:        %s\n", c.ID, c.Customer, c.Tier)
	if len(c.Features) > 0 {
		fmt.Printf("  extras:      %v\n", c.Features)
	}
	if c.TenantBand > 0 {
		fmt.Printf("  tenant band: %d\n", c.TenantBand)
	}
	fmt.Printf("  issued:      %s\n  expires:     %s\n", c.IssuedAt.Format(time.RFC3339), c.ExpiresAt.Format(time.RFC3339))
	return nil
}
