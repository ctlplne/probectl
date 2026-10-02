// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Tenant audit head anchor (AUD-01). The per-tenant hash chain and its durable
// head (audit_stream_heads) both live inside Postgres, so a writer with direct
// table access — the compose stack's login user, a DB superuser — can rewrite a
// row, recompute computeHash across the suffix, and UPDATE audit_stream_heads to
// match. The hash-chain check in TenantVerify then walks that internally
// consistent forgery and still returns nil: nothing OUTSIDE the database's trust
// domain vouches for the chain.
//
// This closes that hole by signing the durable head with the control plane's
// EXISTING offline Ed25519 WORM key (the same key ResolveWormSigningKey returns;
// no new key, no external notary, no phone-home — docs/guardrails.md G7-2/G7-3).
// The PRIVATE half stays in the control plane (Go) and is NEVER written to the
// database or a SQL function (docs/guardrails.md G7-7): the SECURITY DEFINER
// head-advance function stores the signature bytes the control plane computed,
// but it cannot produce them. A DB writer who rewrites rows, recomputes the
// chain, and updates the head therefore cannot forge the signature over the new
// head — so TenantVerify's signature check fails and names the head position.

// headAnchorSigner holds the Ed25519 key material that anchors tenant audit
// stream heads. nil means head anchoring is not configured (WORM signing
// disabled): the chain is then verified hash-only, exactly as before AUD-01 —
// the documented legacy/feature-off fallback.
type headAnchorSigner struct {
	privPEM []byte
	pubPEM  []byte
}

// configuredHeadAnchor is set once at control-plane startup from the resolved
// WORM key (see cmd/probectl-control wiring) and read on every tenant append and
// verify. It is a package-global in the same spirit as auditNow: production sets
// it once, in-package tests swap and restore it.
var configuredHeadAnchor atomic.Pointer[headAnchorSigner]

// ConfigureTenantHeadAnchor installs the WORM Ed25519 key as the tenant audit
// head anchor. It is wired once at control-plane startup from the SAME persisted
// key ResolveWormSigningKey returns, so the provider WORM chain and the tenant
// head anchor share one offline key. Passing empty PEMs clears it (head
// anchoring off → hash-only verification, the pre-AUD-01 behavior). Both halves
// are parsed up front so a malformed key fails loudly at wiring time, never
// silently at the first append.
func ConfigureTenantHeadAnchor(privPEM, pubPEM []byte) error {
	if len(privPEM) == 0 && len(pubPEM) == 0 {
		configuredHeadAnchor.Store(nil)
		return nil
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		return fmt.Errorf("audit: tenant head anchor requires both the private and public WORM key halves")
	}
	if _, err := crypto.ParseEd25519PrivatePEM(privPEM); err != nil {
		return fmt.Errorf("audit: tenant head anchor private key: %w", err)
	}
	if _, err := crypto.ParseEd25519PublicPEM(pubPEM); err != nil {
		return fmt.Errorf("audit: tenant head anchor public key: %w", err)
	}
	configuredHeadAnchor.Store(&headAnchorSigner{privPEM: privPEM, pubPEM: pubPEM})
	return nil
}

// headAnchorMessage is the canonical, domain-separated byte sequence signed over
// a tenant's durable head. The leading label keeps this signature from ever
// being confused with a WORM segment signature (which signs JSON). tenant ids
// are UUIDs and head hashes are hex, so neither field can contain the newline
// delimiter; the format is therefore unambiguous without escaping.
func headAnchorMessage(tenantID string, headSeq int64, headHash string) []byte {
	return []byte("probectl.audit.tenant-head.v1\n" +
		tenantID + "\n" +
		strconv.FormatInt(headSeq, 10) + "\n" +
		headHash + "\n")
}

// signTenantHead returns the Ed25519 signature over the canonical head when a
// head anchor is configured, or (nil, nil) when it is not (the unsigned
// legacy/feature-off path). The signature is computed here, in the control
// plane, and only the resulting bytes ever travel to the database (G7-7).
func signTenantHead(tenantID string, headSeq int64, headHash string) ([]byte, error) {
	anchor := configuredHeadAnchor.Load()
	if anchor == nil {
		return nil, nil
	}
	sig, err := crypto.SignEd25519(anchor.privPEM, headAnchorMessage(tenantID, headSeq, headHash))
	if err != nil {
		return nil, fmt.Errorf("audit: sign tenant head anchor: %w", err)
	}
	return sig, nil
}

// verifyTenantHeadAnchor proves the durable head was signed by the control
// plane's offline WORM key (AUD-01). It runs AFTER the hash-chain check, which
// is self-contained in the database and therefore blind to a writer that
// rewrites a row, recomputes the chain, and updates audit_stream_heads to match.
// The Ed25519 signature over (tenant_id, head_seq, head_hash) cannot be forged
// without the private key — which never leaves the control plane — so that same
// rewrite fails here.
//
// When no anchor is configured (WORM signing disabled) verification is hash-only,
// exactly as before AUD-01. When an anchor IS configured, every head this
// control plane advanced carries a signature, so an absent signature is either a
// legacy head written before the head_sig column existed (re-signed on its next
// append) or a writer that stripped the signature to dodge the check — both fail
// closed, naming the head sequence.
func verifyTenantHeadAnchor(tenantID string, head streamHead) error {
	if head.HeadSeq == 0 {
		return nil // empty chain: nothing appended, nothing to anchor.
	}
	anchor := configuredHeadAnchor.Load()
	if anchor == nil {
		return nil
	}
	if len(head.HeadSig) == 0 {
		return fmt.Errorf(
			"tenant audit head anchor missing at seq %d: durable head is not signed by the control-plane WORM key (tamper, or a legacy head not yet re-anchored by an append)",
			head.HeadSeq,
		)
	}
	ok, err := crypto.VerifyEd25519(anchor.pubPEM, headAnchorMessage(tenantID, head.HeadSeq, head.HeadHash), head.HeadSig)
	if err != nil {
		return fmt.Errorf("tenant audit head anchor unverifiable at seq %d: %w", head.HeadSeq, err)
	}
	if !ok {
		return fmt.Errorf(
			"tenant audit head anchor invalid at seq %d: signature does not match the durable head (row rewritten and hash chain recomputed)",
			head.HeadSeq,
		)
	}
	return nil
}
