// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command probectl-license is the issuer-side license tool (S-T0): generate
// signing keypairs, sign license files, and verify/inspect them. The private
// key is the founder's crown jewel — it lives OFFLINE, never in the repo,
// never on a server (docs/guardrails.md G7-6). Verification inside the
// product uses only the build-time-baked public keys.
//
// Usage:
//
//	probectl-license gen-key  -out-priv license-signing.key -out-pub license-signing.pub
//	probectl-license sign     -key license-signing.key -customer "Acme Corp" \
//	    -tier enterprise -expires 2027-06-30 [-pricing-model flat] \
//	    [-features byok,...] [-tenant-band 25] \
//	    -out probectl-license.json
//	probectl-license verify   -file probectl-license.json -pub license-signing.pub
//	probectl-license verify   -file probectl-license.json   # against THIS build's baked anchors
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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
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
	fmt.Printf("bake into release builds with:\n  -ldflags \"-X github.com/ctlplne/probectl/internal/license.builtinPubKeysB64=%s\"\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "signing private key (PEM)")
	customer := fs.String("customer", "", "customer name")
	id := fs.String("id", "", "license id (default lic_<unix>)")
	tier := fs.String("tier", "", "enterprise | msp")
	pricingModel := fs.String("pricing-model", "", "informational pricing model: flat | consumption (default implied by tier)")
	features := fs.String("features", "", "comma-separated explicit extras (bespoke deals)")
	band := fs.Int("tenant-band", 0, "MSP tenant band (0 = unlimited)")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD (UTC end of day)")
	issued := fs.String("issued", "", "issue date YYYY-MM-DD (UTC start of day; default: now) — re-issue with the original date, or mint an already-expired file for a grace/read-only drill")
	out := fs.String("out", "probectl-license.json", "license file output path")
	_ = fs.Parse(args)

	if *keyPath == "" || *customer == "" || *tier == "" || *expires == "" {
		return fmt.Errorf("sign requires -key, -customer, -tier, -expires")
	}
	licenseTier := license.Tier(*tier)
	if licenseTier != license.TierEnterprise && licenseTier != license.TierMSP {
		return fmt.Errorf("-tier must be enterprise or msp")
	}
	model := license.PricingModel(*pricingModel)
	if model == "" {
		model = license.DefaultPricingModel(licenseTier)
	}
	if model != license.PricingModelFlat && model != license.PricingModelConsumption {
		return fmt.Errorf("-pricing-model must be flat or consumption")
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	exp, err := time.Parse("2006-01-02", *expires)
	if err != nil {
		return fmt.Errorf("parse -expires: %w", err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	if *issued != "" {
		day, err := time.Parse("2006-01-02", *issued)
		if err != nil {
			return fmt.Errorf("parse -issued: %w", err)
		}
		issuedAt = day.UTC()
	}
	expiresAt := exp.Add(24*time.Hour - time.Second).UTC()
	if !expiresAt.After(issuedAt) {
		// Verify() rejects an inverted window anyway; say it at signing time so
		// the vendor never hands out a file that fails to load.
		return fmt.Errorf("-expires (%s) must be after -issued (%s)", expiresAt.Format("2006-01-02"), issuedAt.Format("2006-01-02"))
	}
	c := license.Claims{
		V:            1,
		ID:           *id,
		Customer:     *customer,
		Tier:         licenseTier,
		PricingModel: model,
		TenantBand:   *band,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
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
	fmt.Printf("wrote %s — %s · %s · %s · issued %s · expires %s\n", *out, c.Customer, c.Tier, c.PricingModel, c.IssuedAt.Format(time.RFC3339), c.ExpiresAt.Format(time.RFC3339))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	file := fs.String("file", "probectl-license.json", "license file")
	pub := fs.String("pub", "", "public key (PEM) to verify against; omitted = the trust anchors baked into THIS probectl-license build (answers: will a control plane from the same build accept the file?)")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var (
		anchors [][]byte
		against string
	)
	if *pub != "" {
		pubPEM, err := os.ReadFile(*pub)
		if err != nil {
			return err
		}
		anchors, against = [][]byte{pubPEM}, "-pub "+*pub
	} else {
		// DPR-024: the vendor CLI is built with the same anchors as the
		// control plane, so a customer can check a file against exactly what
		// the shipped build trusts, without extracting a public key first.
		anchors = license.TrustedKeys()
		if len(anchors) == 0 {
			return fmt.Errorf("verify: no -pub given and this probectl-license build carries no license trust anchors (keyless build); pass -pub <signing.pub>, or build with the committed trusted_keys/*.pub or PROBECTL_LICENSE_PUBKEYS_B64")
		}
		against = fmt.Sprintf("%d baked trust anchor(s)", len(anchors))
	}
	c, err := license.Verify(raw, anchors)
	if err != nil {
		return err
	}
	fmt.Printf("VALID — %s · %s · %s · expires %s (verified against %s)\n", c.Customer, c.Tier, c.PricingModel, c.ExpiresAt.Format(time.RFC3339), against)
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
	model := c.PricingModel
	if model == "" {
		model = license.DefaultPricingModel(c.Tier)
	}
	fmt.Printf("  id:            %s\n  customer:      %s\n  tier:          %s\n  pricing model: %s\n", c.ID, c.Customer, c.Tier, model)
	if len(c.Features) > 0 {
		fmt.Printf("  extras:        %v\n", c.Features)
	}
	if c.TenantBand > 0 {
		fmt.Printf("  tenant band:   %d\n", c.TenantBand)
	}
	fmt.Printf("  issued:        %s\n  expires:       %s\n", c.IssuedAt.Format(time.RFC3339), c.ExpiresAt.Format(time.RFC3339))
	return nil
}
