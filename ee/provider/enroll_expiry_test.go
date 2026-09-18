// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Commercial component. See ee/LICENSE. Not covered by the MPL-2.0 core
// license; use requires a probectl commercial license.

package provider

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DPR-178: an unredeemed operator enrollment token used to be valid forever.
// The hash is single-use and never stored in plaintext, but until someone
// redeemed it the message carrying it stayed a live credential for the
// product's highest-privilege domain. The agent side of the same idea has
// always been an hour.
func TestOperatorEnrollmentTokenExpires(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	token := "enroll-token-under-test"
	hash := crypto.Hash([]byte(token))

	op, err := store.CreateOperator(ctx, Operator{Email: "noc@example.com", Role: RoleOperator}, hash)
	if err != nil {
		t.Fatal(err)
	}

	// Inside the window it is a token.
	if _, err := store.OperatorByEnrollHash(ctx, hash); err != nil {
		t.Fatalf("a freshly minted enrollment token was refused: %v", err)
	}

	// Past the window it is not, and the refusal is the same "no such token"
	// every wrong hash gets — an expired token must not be distinguishable from
	// an invented one.
	store.mu.Lock()
	store.operators[op.ID].enrollExpires = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if _, err := store.OperatorByEnrollHash(ctx, hash); err == nil {
		t.Fatal("an expired enrollment token was still accepted")
	} else if err != ErrNotFound {
		t.Fatalf("an expired token must be refused as not-found, got %v", err)
	}

	// A token with no recorded window is refused too: rows written before the
	// window existed are not immortal credentials.
	store.mu.Lock()
	store.operators[op.ID].enrollExpires = time.Time{}
	store.mu.Unlock()
	if _, err := store.OperatorByEnrollHash(ctx, hash); err == nil {
		t.Fatal("an enrollment token with no expiry was accepted")
	}
}

// The window has to be long enough to install an authenticator and short enough
// that a forgotten invitation stops being a way in.
func TestOperatorEnrollTTLIsBounded(t *testing.T) {
	if OperatorEnrollTTL < time.Hour {
		t.Fatalf("OperatorEnrollTTL = %s: too short for a person who must install an authenticator", OperatorEnrollTTL)
	}
	if OperatorEnrollTTL > 7*24*time.Hour {
		t.Fatalf("OperatorEnrollTTL = %s: a week-old invitation is not a credential anyone is still watching", OperatorEnrollTTL)
	}
}

// DPR-178, second half: the window has to travel WITH the token. The fix gave
// the token a 24-hour life and said so in the OpenAPI document —
// "the response carries ... enroll_token_expires_in" — while both handlers went
// on returning two fields, and the route documented a 200 it never sends. A
// description is not an implementation, and a recipient who cannot date a
// one-time credential will try to redeem it next week.
//
// The spec is the oracle here rather than a second copy of the list.
func TestOperatorEnrollmentResponseMatchesTheDocumentedSchema(t *testing.T) {
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("openapi.json does not parse: %v", err)
	}

	// Both operator-creating routes must document the 201 they actually send,
	// pointing at the same body.
	for _, route := range []string{"/provider/v1/operators", "/provider/v1/auth/bootstrap"} {
		op, ok := spec.Paths[route]["post"]
		if !ok {
			t.Fatalf("%s has no documented POST", route)
		}
		res, ok := op.Responses["201"]
		if !ok {
			t.Errorf("%s documents %v but the handler returns 201 Created", route, keysOf(op.Responses))
			continue
		}
		ref := res.Content["application/json"].Schema.Ref
		if ref != "#/components/schemas/OperatorEnrollment" {
			t.Errorf("%s 201 body schema = %q, want the shared OperatorEnrollment", route, ref)
		}
	}

	schema, ok := spec.Components.Schemas["OperatorEnrollment"]
	if !ok {
		t.Fatal("OperatorEnrollment schema is missing, so the response body is undocumented")
	}

	// And the handler's own body must carry every field the schema requires. This
	// is the assertion that was missing: the field list came from the handler, the
	// promise came from the spec, and nothing compared them.
	body := enrollTokenResponse(Operator{Email: "ops@example.test", Role: RoleAdmin}, "one-time-token")
	for _, want := range schema.Required {
		if _, ok := body[want]; !ok {
			t.Errorf("the response body omits %q, which openapi.json marks required", want)
		}
		if _, ok := schema.Properties[want]; !ok {
			t.Errorf("%q is required but has no property definition", want)
		}
	}
	for got := range body {
		if _, ok := schema.Properties[got]; !ok {
			t.Errorf("the handler sends %q and openapi.json does not document it", got)
		}
	}

	// The window itself must be the real one, not a hard-coded string that can
	// drift from OperatorEnrollTTL.
	if body["enroll_token_expires_in"] != OperatorEnrollTTL.String() {
		t.Errorf("enroll_token_expires_in = %v, want %s", body["enroll_token_expires_in"], OperatorEnrollTTL)
	}
	at, err := time.Parse(time.RFC3339, body["enroll_token_expires_at"].(string))
	if err != nil {
		t.Fatalf("enroll_token_expires_at is not RFC3339: %v", err)
	}
	if d := time.Until(at); d < OperatorEnrollTTL-time.Minute || d > OperatorEnrollTTL+time.Minute {
		t.Errorf("enroll_token_expires_at is %s away, want about %s", d, OperatorEnrollTTL)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
