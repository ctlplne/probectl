// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import "testing"

// TestAUD03HeaderFieldsAreUnambiguous is the AUD-03 regression for the hash
// pre-image (docs/guardrails.md G7-N). The chained header newline-joins its
// string fields; before escaping, a newline inside one field could shift a
// delimiter, so two DISTINCT (actor, action) tuples serialized to the same bytes
// and collided to the same hash — letting a tamperer move text across the
// actor/action boundary without breaking the chain. The header must now encode
// each field unambiguously, so the two tuples below produce different hashes.
func TestAUD03HeaderFieldsAreUnambiguous(t *testing.T) {
	const (
		stream = "11111111-1111-1111-1111-111111111111"
		seq    = int64(7)
		target = "target"
		micros = int64(1_700_000_000_000_000)
		prev   = ""
	)

	// Everything identical except WHERE the newline splits actor/action:
	//   (actor="a\nb", action="c")  vs  (actor="a", action="b\nc").
	// A raw newline join renders both as "...\na\nb\nc\n..." — a collision.
	h1, err := computeHash(stream, seq, "a\nb", "c", target, micros, nil, prev)
	if err != nil {
		t.Fatalf("computeHash (actor=%q action=%q): %v", "a\nb", "c", err)
	}
	h2, err := computeHash(stream, seq, "a", "b\nc", target, micros, nil, prev)
	if err != nil {
		t.Fatalf("computeHash (actor=%q action=%q): %v", "a", "b\nc", err)
	}
	if h1 == h2 {
		t.Fatalf(
			"audit hash header is newline-ambiguous: (actor=%q,action=%q) and (actor=%q,action=%q) both hash to %s",
			"a\nb", "c", "a", "b\nc", h1,
		)
	}

	// Escaping is the IDENTITY for a field with no newline/backslash, so a value
	// that merely shares a prefix with an escaped one must NOT collide either and
	// honest chains (no control bytes in any field) keep their pre-AUD-03 hashes.
	// A backslash must likewise not be confusable with an escaped newline.
	h3, err := computeHash(stream, seq, `a\nb`, "c", target, micros, nil, prev)
	if err != nil {
		t.Fatalf("computeHash (actor=%q action=%q): %v", `a\nb`, "c", err)
	}
	if h3 == h1 {
		t.Fatalf("literal backslash-n confused with a newline: %q and %q collide to %s", `a\nb`, "a\nb", h1)
	}
}
