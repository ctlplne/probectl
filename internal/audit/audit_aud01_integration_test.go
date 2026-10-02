// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package audit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAudlogTamperMatrix is the AUD-01 regression: a DB writer with direct table
// access (the compose stack's login user / a superuser) rewrites a row,
// recomputes the WHOLE hash chain through the head with computeHash, AND updates
// audit_stream_heads to match — so the self-contained hash-chain check still
// passes — WITHOUT any SIEM cursor present. Each matrix scenario differs only in
// what it does with the out-of-trust-domain Ed25519 head signature. Before this
// fix (hash chain only, no head_sig column) every one of these passes verify
// (the vulnerability). With the control plane's WORM key anchoring the head, the
// writer cannot forge the signature over the recomputed head, so TenantVerify
// returns an error naming the head sequence.
//
// Scenarios (named for the parked tamper matrix S6/S8/S9/S10):
//
//	S6  rewrite a middle row, recompute the chain, advance the head, and LEAVE
//	    the original signature (the naive writer) → signature no longer matches.
//	S8  same, and STRIP the signature to NULL hoping verify falls back to
//	    hash-only → fail closed on the missing anchor, never a silent pass.
//	S9  same, and overwrite the signature with 64 bytes of attacker-chosen
//	    garbage → signature does not verify.
//	S10 same, and re-sign the recomputed head with the ATTACKER'S OWN Ed25519
//	    key (a well-formed signature from the wrong key) → does not verify under
//	    the control plane's public key.
func TestAudlogTamperMatrix(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// The tenant head anchor is a package-global set once at control-plane
	// startup (headanchor.go); swap in a generated WORM key for this test and
	// restore whatever was configured before, so other suites are unaffected.
	wormPriv, wormPub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate WORM anchor key: %v", err)
	}
	prevAnchor := configuredHeadAnchor.Load()
	defer configuredHeadAnchor.Store(prevAnchor)
	if err := ConfigureTenantHeadAnchor(wormPriv, wormPub); err != nil {
		t.Fatalf("configure tenant head anchor: %v", err)
	}

	// An unrelated attacker key, for the S10 wrong-key forgery.
	attackerPriv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	scenarios := []struct {
		name string
		// tamperHeadSig returns the head_sig bytes the writer leaves behind after
		// rewriting + re-chaining to the new head (tenant, newHeadSeq, newHeadHash).
		// origSig is the authentic signature present before the attack.
		tamperHeadSig func(t *testing.T, tenantID string, newHeadSeq int64, newHeadHash string, origSig []byte) any
	}{
		{
			name: "S6_leave_stale_signature",
			tamperHeadSig: func(_ *testing.T, _ string, _ int64, _ string, origSig []byte) any {
				return origSig // authentic signature, but over the PRE-tamper head
			},
		},
		{
			name: "S8_strip_signature_to_null",
			tamperHeadSig: func(_ *testing.T, _ string, _ int64, _ string, _ []byte) any {
				return nil // NULL head_sig: hope verify falls back to hash-only
			},
		},
		{
			name: "S9_garbage_signature",
			tamperHeadSig: func(t *testing.T, _ string, _ int64, _ string, _ []byte) any {
				forged := make([]byte, crypto.Ed25519SignatureSize)
				if _, err := rand.Read(forged); err != nil {
					t.Fatalf("random forged signature: %v", err)
				}
				return forged
			},
		},
		{
			name: "S10_wrong_key_signature",
			tamperHeadSig: func(t *testing.T, tenantID string, newHeadSeq int64, newHeadHash string, _ []byte) any {
				sig, err := crypto.SignEd25519(attackerPriv, headAnchorMessage(tenantID, newHeadSeq, newHeadHash))
				if err != nil {
					t.Fatalf("attacker sign: %v", err)
				}
				return sig
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tn, err := store.NewTenants(pool).Create(
				ctx, fmt.Sprintf("aud01-%s-%d", sc.name, time.Now().UnixNano()), "Aud01",
			)
			if err != nil {
				t.Fatalf("create tenant: %v", err)
			}
			tid := tenancy.ID(tn.ID)

			// Append five events through the real, signing append path and prove
			// the honest chain (hash + head signature) verifies.
			if err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
				for i := 0; i < 5; i++ {
					if _, err := TenantAppend(ctx, s, "alice", "tenant.update", fmt.Sprintf("target-%d", i), map[string]any{"i": i}); err != nil {
						return err
					}
				}
				return TenantVerify(ctx, s)
			}); err != nil {
				t.Fatalf("append + verify (honest, signed chain): %v", err)
			}

			// No SIEM cursor exists for this fresh tenant — exactly the finding's
			// precondition ("WITHOUT any SIEM cursor present").
			var cursors int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM siem_delivery WHERE tenant_id = $1`, tn.ID).Scan(&cursors); err != nil {
				t.Fatalf("siem cursor probe: %v", err)
			}
			if cursors != 0 {
				t.Fatalf("precondition broken: %d SIEM cursor rows exist", cursors)
			}

			// Capture the authentic head signature before tampering.
			var origSig []byte
			if err := pool.QueryRow(ctx,
				`SELECT head_sig FROM audit_stream_heads WHERE tenant_id = $1`, tn.ID).Scan(&origSig); err != nil {
				t.Fatalf("read authentic head sig: %v", err)
			}
			if len(origSig) != crypto.Ed25519SignatureSize {
				t.Fatalf("honest head must be signed, got %d-byte sig", len(origSig))
			}

			// As the DB writer (superuser pool, bypassing append-only RLS): rewrite
			// seq 3's actor, recompute prev_hash/hash for seq 3..5 with computeHash,
			// and advance the durable head hash to the recomputed tail.
			newHeadHash := rewriteAndRechainTenantChain(ctx, t, pool, tn.ID, 3, "mallory")
			if _, err := pool.Exec(ctx,
				`UPDATE audit_stream_heads SET head_hash = $2 WHERE tenant_id = $1`,
				tn.ID, newHeadHash); err != nil {
				t.Fatalf("advance head to recomputed tail: %v", err)
			}

			// Scenario-specific head_sig manipulation.
			tamperedSig := sc.tamperHeadSig(t, tn.ID, 5, newHeadHash, origSig)
			if _, err := pool.Exec(ctx,
				`UPDATE audit_stream_heads SET head_sig = $2 WHERE tenant_id = $1`,
				tn.ID, tamperedSig); err != nil {
				t.Fatalf("set tampered head sig: %v", err)
			}

			// The recomputed hash chain is internally consistent and the head row
			// matches it — so the pre-AUD-01 hash-only verify PASSES. The head
			// signature check must now fail, naming the head sequence (5).
			verr := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, TenantVerify)
			if verr == nil {
				t.Fatalf("%s: TenantVerify accepted a rewritten+rechained chain (AUD-01 not enforced)", sc.name)
			}
			if !strings.Contains(verr.Error(), "head anchor") || !strings.Contains(verr.Error(), "seq 5") {
				t.Fatalf("%s: verify error must name the head anchor and tampered seq 5, got: %v", sc.name, verr)
			}
			t.Logf("%s: recomputed-chain tamper correctly rejected by the head anchor: %v", sc.name, verr)
		})
	}
}

// rewriteAndRechainTenantChain is the AUD-01 attacker move run as the DB writer:
// it rewrites the actor of rewriteSeq, then recomputes prev_hash/hash for every
// row from rewriteSeq to the head with computeHash — producing an internally
// consistent chain that the self-contained hash check accepts — and returns the
// recomputed head hash. It touches only audit_events; the caller advances the
// durable head and manipulates the signature.
func rewriteAndRechainTenantChain(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenantID any, rewriteSeq int64, newActor string) string {
	t.Helper()

	type row struct {
		seq                   int64
		actor, action, target string
		data                  map[string]any
		prevHash              string
		createdAt             time.Time
	}
	rows, err := pool.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, created_at
		   FROM audit_events WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain []row
	for rows.Next() {
		var r row
		var dataBytes []byte
		if err := rows.Scan(&r.seq, &r.actor, &r.action, &r.target, &dataBytes, &r.prevHash, &r.createdAt); err != nil {
			rows.Close()
			t.Fatalf("scan chain row: %v", err)
		}
		if len(dataBytes) > 0 {
			if err := json.Unmarshal(dataBytes, &r.data); err != nil {
				rows.Close()
				t.Fatalf("decode data: %v", err)
			}
		}
		chain = append(chain, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("chain rows: %v", err)
	}

	tid := fmt.Sprintf("%v", tenantID)
	var prev string
	var newHeadHash string
	for i := range chain {
		r := &chain[i]
		if r.seq < rewriteSeq {
			prev = recomputeStoredHash(ctx, t, pool, tenantID, r.seq)
			continue
		}
		if r.seq == rewriteSeq {
			r.actor = newActor
		} else {
			r.prevHash = prev // chain onto the recomputed predecessor
		}
		h, err := computeHash(tid, r.seq, r.actor, r.action, r.target, r.createdAt.UnixMicro(), r.data, r.prevHash)
		if err != nil {
			t.Fatalf("recompute hash seq %d: %v", r.seq, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE audit_events SET actor = $3, prev_hash = $4, hash = $5 WHERE tenant_id = $1 AND seq = $2`,
			tenantID, r.seq, r.actor, r.prevHash, h); err != nil {
			t.Fatalf("write recomputed seq %d: %v", r.seq, err)
		}
		prev = h
		newHeadHash = h
	}
	if newHeadHash == "" {
		t.Fatalf("rewriteSeq %d not found in chain", rewriteSeq)
	}
	return newHeadHash
}

// recomputeStoredHash returns a row's current stored hash (the predecessor link
// for the first rewritten row, which is left untouched).
func recomputeStoredHash(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenantID any, seq int64) string {
	t.Helper()
	var h string
	if err := pool.QueryRow(ctx,
		`SELECT hash FROM audit_events WHERE tenant_id = $1 AND seq = $2`, tenantID, seq).Scan(&h); err != nil {
		t.Fatalf("read stored hash seq %d: %v", seq, err)
	}
	return h
}
