// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/scim"
)

func FuzzDecodeSCIM(f *testing.F) {
	for _, seed := range scimDecodeSeeds() {
		f.Add(seed.kind, seed.body)
	}

	f.Fuzz(func(t *testing.T, kind string, body []byte) {
		if len(body) > scimMaxBody+1 {
			return
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/fuzz", bytes.NewReader(body))
		ok := decodeSCIM(rec, req, scimDecodeTarget(kind))
		if ok {
			return
		}
		switch rec.Code {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		default:
			t.Fatalf("decodeSCIM failed with status %d, want 400 or 413", rec.Code)
		}
	})
}

func scimDecodeTarget(kind string) any {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "user":
		return &scim.User{}
	case "group":
		return &scim.Group{}
	default:
		return &scim.PatchOp{}
	}
}

func scimDecodeSeeds() []struct {
	kind string
	body []byte
} {
	return []struct {
		kind string
		body []byte
	}{
		{kind: "patch", body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)},
		{kind: "patch", body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Eng"}]}`)},
		{kind: "user", body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@example.com","active":true,"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"NetOps"}}`)},
		{kind: "group", body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineers","members":[{"value":"u1"},{"value":"u2"}]}`)},
		{kind: "user", body: []byte(`{"userName":"a"} {"userName":"b"}`)},
		{kind: "group", body: []byte(`{"displayName":"unterminated"`)},
		{kind: "patch", body: []byte(`not json`)},
		{kind: "patch", body: []byte(`[]`)},
	}
}
