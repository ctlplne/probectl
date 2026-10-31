// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func subjectSelectionIntent(t *testing.T, f activityFixture, aliases []string) Invalidation {
	t.Helper()
	ctx := f.operational(t, f.red.scope.TenantID)
	plan, err := f.red.codec.PrepareSubjectErasurePlan(ctx, mustInvalidationUUID(t), "subject@example.test", aliases)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.journal.BeginSubjectInvalidation(ctx, f.red.codec, plan, allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

// This fixture validates its entire small generic frame. It deliberately does
// not certify production native question/proposal documents or controller
// erasure credentials; their typed projector is mandatory integration work.
type subjectSelectionProbe struct {
	bodies   [][]byte
	released bool
	plan     SubjectErasurePlan
	after    func()
}

func (p *subjectSelectionProbe) factory(_ context.Context, plan SubjectErasurePlan) (subjectDocumentMatch, func(), error) {
	p.plan = plan
	aliases := slices.Clone(plan.value.wire.Aliases)
	return func(_ context.Context, _ StoredMessage, body []byte) (bool, error) {
		p.bodies = append(p.bodies, body)
		var frame struct {
			Question string          `json:"question"`
			Exact    json.RawMessage `json:"exact"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&frame); err != nil || frame.Question == "" {
			return false, ErrMessageIntegrity
		}
		if _, err := decoder.Token(); err != io.EOF {
			return false, ErrMessageIntegrity
		}
		selected := slices.Contains(aliases, frame.Question)
		if p.after != nil {
			p.after()
		}
		return selected, nil
	}, func() { clear(aliases); p.released = true }, nil
}

func (p *subjectSelectionProbe) assertDrained(t *testing.T, f activityFixture) {
	t.Helper()
	if !p.released || p.plan.value == nil || p.plan.value.wire.Subject != "" || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("matching factory/selector/activity survived actual return")
	}
	for _, body := range p.bodies {
		if !bytes.Equal(body, make([]byte, len(body))) {
			t.Fatal("borrowed authenticated body survived matching")
		}
	}
	if _, err := f.journal.CandidateEpoch(f.red.requestContext(t)); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("selection cleared the exact pending refusal marker", err)
	}
	if _, err := f.journal.Lookup(f.blue.requestContext(t), f.blue.scope.ConversationID, Revision{MessageID: f.blue.scope.MessageID, Revision: f.blue.scope.Revision}, 1<<20, f.blue.authorizeHistory); err != nil {
		t.Fatal("subject matching changed healthy sibling history", err)
	}
}

func selectionFixtureID(n int) string {
	// Keyset order is deliberate and unrelated to conversation position.
	const digits = "0123456789abcdef"
	return "00000000-0000-4000-8000-00000000000" + string(digits[n])
}

func seedSelectionMetadata(t *testing.T, journal *Journal, fixture messageCodecFixture, question string, meta InputMetadata) messageCodecFixture {
	t.Helper()
	body, err := json.Marshal(map[string]any{"question": question, "exact": json.RawMessage("18446744073709551617")})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	prepared, err := fixture.codec.PrepareInput(fixture.requestContext(t), fixture.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, body, fixture.authorize)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(fixture.requestContext(t), prepared, fixture.authorize); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func seedSelectionChain(t *testing.T, f activityFixture, expires time.Time) (messageCodecFixture, messageCodecFixture, messageCodecFixture) {
	t.Helper()
	base := time.Now().UTC().Add(-time.Minute)
	root, mid, leaf := f.red, f.red, f.red
	root.scope.MessageID, mid.scope.MessageID, leaf.scope.MessageID = selectionFixtureID(14), selectionFixtureID(13), selectionFixtureID(12)
	root = seedSelectionMetadata(t, f.journal, root, "subject@example.test", InputMetadata{FrozenAt: base, ExpiresAt: expires})
	mid = seedSelectionMetadata(t, f.journal, mid, "neutral middle", InputMetadata{FrozenAt: base.Add(time.Second), ExpiresAt: expires, Parent: &Revision{MessageID: root.scope.MessageID, Revision: root.scope.Revision}})
	leaf = seedSelectionMetadata(t, f.journal, leaf, "neutral leaf", InputMetadata{FrozenAt: base.Add(2 * time.Second), ExpiresAt: expires, Parent: &Revision{MessageID: mid.scope.MessageID, Revision: mid.scope.Revision}})
	return root, mid, leaf
}

func TestHistoryJournalPostgresSubjectSelectionCompleteExpiredAncestry(t *testing.T) {
	for _, positive := range []bool{true, false} {
		name := "unmatched_pages_reach_actual_EOF"
		if positive {
			name = "expired_deep_descendant_after_unmatched_pages"
		}
		t.Run(name, func(t *testing.T) {
			f := newActivityFixture(t)
			if f.admin == nil {
				return
			}
			for i := range 5 {
				neutral := f.red
				neutral.scope.MessageID = selectionFixtureID(i)
				seedSelectionMetadata(t, f.journal, neutral, "neutral unrelated", inputMetadata())
			}
			seedSubjectOperation(t, f.journal, f.blue, time.Time{})
			var leaf messageCodecFixture
			if positive {
				expires := time.Now().Add(2 * time.Second)
				_, _, leaf = seedSelectionChain(t, f, expires)
				select {
				case <-time.After(time.Until(expires) + 10*time.Millisecond):
				case <-t.Context().Done():
					t.Fatal("fixture expiry wait canceled")
				}
			}
			pending := subjectSelectionIntent(t, f, nil)
			probe := &subjectSelectionProbe{}
			selection, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
			if err != nil {
				t.Fatal("complete subject traversal failed", err)
			}
			if positive {
				if selection.exhausted || len(selection.leaves) != 1 || selection.leaves[0].Scope() != leaf.scope || selection.scanned != 6 || !selection.leaves[0].Metadata().ExpiresAt.Before(time.Now()) || selection.leaves[0].Ciphertext().parts == nil {
					t.Fatal("empty match page, expiry or total-history cap hid the exact inherited leaf")
				}
			} else if !selection.exhausted || len(selection.leaves) != 0 || selection.scanned != 5 || len(probe.bodies) != 5 {
				t.Fatal("zero matches were not proven by actual tenant-scoped EOF")
			}
			probe.assertDrained(t, f)
			if positive {
				// With room for the complete small fixture, verify every row,
				// not only selected leaves, and reach actual EOF explicitly.
				probe = &subjectSelectionProbe{}
				selection, err = f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 16, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
				if err != nil || !selection.exhausted || selection.scanned != 8 || len(selection.leaves) != 1 || selection.leaves[0].Scope() != leaf.scope {
					t.Fatal("complete scan lost a non-leaf/ancestor or fabricated EOF", err)
				}
				probe.assertDrained(t, f)
			}
		})
	}
}

func TestHistoryJournalPostgresSubjectSelectionRefusesUnknownSource(t *testing.T) {
	for _, fault := range []string{"owner_bad_document", "direct_match_bad_ancestor", "nonleaf_cycle", "intermediate_clock_inversion", "ancestor_byte_budget", "revoked_after_decryption", "missing_factory_cleanup"} {
		t.Run(fault, func(t *testing.T) {
			f := newActivityFixture(t)
			if f.admin == nil {
				return
			}
			root, mid, leaf := seedSelectionChain(t, f, time.Now().Add(time.Hour))
			seedSubjectOperation(t, f.journal, f.blue, time.Time{})
			aliases := []string(nil)
			if fault == "owner_bad_document" {
				aliases = []string{f.red.scope.OwnerID}
			}
			if fault == "owner_bad_document" || fault == "direct_match_bad_ancestor" {
				bad, err := root.codec.Seal(root.context, root.scope, root.origin, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"wrong_frame":"private"}`))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET private_header=$3,private_payload=$4 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, root.scope.TenantID, root.scope.MessageID, bad.parts.header, bad.parts.payload); err != nil {
					t.Fatal(err)
				}
				if fault == "direct_match_bad_ancestor" {
					body, err := leaf.codec.Seal(leaf.context, leaf.scope, leaf.origin, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"subject@example.test"}`))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET private_header=$3,private_payload=$4 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, leaf.scope.TenantID, leaf.scope.MessageID, body.parts.header, body.parts.payload); err != nil {
						t.Fatal(err)
					}
				}
			}
			if fault == "nonleaf_cycle" {
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET parent_message_id=$3::uuid,parent_revision=$4 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, root.scope.TenantID, root.scope.MessageID, leaf.scope.MessageID, int64(leaf.scope.Revision)); err != nil {
					t.Fatal(err)
				}
				var leaves int
				if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM flow_conversation_messages m WHERE m.tenant_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM flow_conversation_messages child WHERE child.tenant_id=m.tenant_id AND child.owner_id=m.owner_id AND child.conversation_id=m.conversation_id AND child.parent_message_id=m.message_id AND child.parent_revision=m.revision)`, root.scope.TenantID).Scan(&leaves); err != nil || leaves != 0 {
					t.Fatal("owned corrupt cycle must have no leaves", err)
				}
			}
			if fault == "intermediate_clock_inversion" {
				// The admitted original clocks differ slightly from wall-clock
				// now. Read the exact middle projection before fault injection.
				var frozen string
				if err := f.admin.QueryRow(t.Context(), `SELECT frozen_at FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, mid.scope.TenantID, mid.scope.MessageID).Scan(&frozen); err != nil {
					t.Fatal(err)
				}
				middle, err := time.Parse(time.RFC3339Nano, frozen)
				if err != nil {
					t.Fatal(err)
				}
				at := middle.Add(500 * time.Millisecond)
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET frozen_at=$3 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, root.scope.TenantID, root.scope.MessageID, at.Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			pending := subjectSelectionIntent(t, f, aliases)
			probe := &subjectSelectionProbe{}
			var allowed atomic.Bool
			allowed.Store(true)
			authorize := func(ctx context.Context, tenant string) error {
				if !allowed.Load() {
					return ErrMessageDenied
				}
				return allowActivityMaintenance(ctx, tenant)
			}
			want := ErrMessageIntegrity
			budget := HistoryBudget{Rows: 1, Bytes: 1 << 20}
			if fault == "ancestor_byte_budget" {
				if err := f.admin.QueryRow(t.Context(), `SELECT `+historyStoredBytes+`+1 FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, leaf.scope.TenantID, leaf.scope.MessageID).Scan(&budget.Bytes); err != nil {
					t.Fatal(err)
				}
				want = ErrMessageBudget
			}
			if fault == "revoked_after_decryption" {
				probe.after = func() { allowed.Store(false) }
				want = ErrMessageDenied
			}
			factory := subjectMatchFactory(probe.factory)
			if fault == "missing_factory_cleanup" {
				factory = func(_ context.Context, plan SubjectErasurePlan) (subjectDocumentMatch, func(), error) {
					probe.plan = plan
					return func(context.Context, StoredMessage, []byte) (bool, error) {
						t.Error("incomplete factory opened source")
						return false, nil
					}, nil, nil
				}
				want = ErrMessageDenied
			}
			selection, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, budget, authorize, factory)
			if !errors.Is(err, want) || selection.exhausted || selection.scanned != 0 || len(selection.leaves) != 0 {
				t.Fatal("unknown source produced a partial/complete or zero-match success", err)
			}
			if fault != "missing_factory_cleanup" {
				probe.assertDrained(t, f)
			} else if len(probe.bodies) != 0 || f.active(t, f.red.scope.TenantID) != 0 || probe.plan.value.wire.Subject != "" {
				t.Fatal("incomplete factory survived source drain")
			}
		})
	}
}

func TestHistoryJournalPostgresSubjectSelectionMissingOldKeyIsNotNoMatch(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.red, time.Time{})
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	clear(key)
	current, err := tenantcrypto.NewEnvelopeSealer("owned-selection-current", encoded)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(current) // source remains under the unavailable old key
	defer tenantcrypto.SetPrimary(f.red.sealer)
	pending := subjectSelectionIntent(t, f, nil) // exact plan uses the current key
	probe := &subjectSelectionProbe{}
	selection, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
	if !errors.Is(err, ErrMessageIntegrity) || selection.exhausted || len(selection.leaves) != 0 || len(probe.bodies) != 0 || !probe.released || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("missing actual old source key became no matches", err)
	}
	overlap, err := tenantcrypto.NewEnvelopeKeyringSealer("owned-selection-current", encoded, map[string]string{"owned-history-test": f.red.key})
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(overlap)
	probe = &subjectSelectionProbe{}
	selection, err = f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 2, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
	if err != nil || !selection.exhausted || len(selection.leaves) != 1 || len(probe.bodies) != 1 {
		t.Fatal("restored actual opener could not resume the exact pending plan", err)
	}
	probe.assertDrained(t, f)
}
