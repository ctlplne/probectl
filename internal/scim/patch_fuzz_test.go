// SPDX-License-Identifier: LicenseRef-probectl-TBD

package scim

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzApplyUserPatch(f *testing.F) {
	for _, seed := range scimPatchSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, body []byte) {
		var ops []PatchOperation
		if err := json.Unmarshal(body, &ops); err != nil {
			return
		}
		u := User{
			UserName:    "old@example.com",
			DisplayName: "Old Name",
			Active:      true,
			Name:        &Name{Formatted: "Old Name"},
		}
		_ = ApplyUserPatch(&u, ops)
	})
}

func FuzzParseGroupPatch(f *testing.F) {
	for _, seed := range scimPatchSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var ops []PatchOperation
		if err := json.Unmarshal(body, &ops); err != nil {
			return
		}
		patch := ParseGroupPatch(ops)
		for _, id := range patch.Add {
			if id == "" {
				t.Fatal("group patch accepted empty add member")
			}
		}
		for _, id := range patch.Remove {
			if id == "" {
				t.Fatal("group patch accepted empty remove member")
			}
		}
		if patch.ReplaceAll != nil {
			for _, id := range *patch.ReplaceAll {
				if id == "" {
					t.Fatal("group patch accepted empty replace member")
				}
			}
		}
	})
}

func scimPatchSeeds() [][]byte {
	return [][]byte{
		{},
		[]byte(`not json`),
		[]byte(`[{"op":"replace","value":{"active":false}}]`),
		[]byte(`[{"op":"Replace","path":"active","value":"False"}]`),
		[]byte(`[{"op":"replace","path":"active","value":"maybe"}]`),
		[]byte(`[{"op":"replace","path":"displayName","value":["nested","shape"]}]`),
		[]byte(`[{"op":"replace","path":"name.formatted","value":{"unexpected":"object"}}]`),
		[]byte(`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`),
		[]byte(`[{"op":"remove","path":"members[value eq \"u3\"]"}]`),
		[]byte(`[{"op":"remove","path":"members[value eq \"unterminated]"}]`),
		[]byte(`[{"op":"replace","path":"members","value":{"value":"u4"}}]`),
		[]byte(`[{"op":"replace","value":{"displayName":"Eng","members":[{"value":"u5"}]}}]`),
		[]byte(memberArrayPatchSeed(64)),
	}
}

func memberArrayPatchSeed(n int) string {
	var b strings.Builder
	b.WriteString(`[{"op":"replace","path":"members","value":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"value":"u`)
		b.WriteString(itoa(i + 1))
		b.WriteString(`"}`)
	}
	b.WriteString(`]}]`)
	return b.String()
}
