// SPDX-License-Identifier: LicenseRef-probectl-TBD

package i18n

import "testing"

func TestResolveFallsBackAndNormalizes(t *testing.T) {
	cases := map[string]string{
		"":            "en",
		"en-US":       "en",
		"es_MX.UTF-8": "es",
		"fr":          "en",
		"  ES-419  ":  "es",
	}
	for raw, want := range cases {
		if got := Resolve(raw); got != want {
			t.Errorf("Resolve(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestTLocalizesAndInterpolates(t *testing.T) {
	got := T("es-MX", "cli.error.unknown", map[string]string{"command": `"wat"`})
	if want := `comando desconocido "wat"`; got != want { //nolint:misspell // Spanish locale copy.
		t.Fatalf("T = %q, want %q", got, want)
	}
	if got := T("zz", "cli.error.unknown", map[string]string{"command": `"wat"`}); got != `unknown command "wat"` {
		t.Fatalf("English fallback = %q", got)
	}
}

func TestErrorMessageLocalizesStableAPICodes(t *testing.T) {
	if got := ErrorMessage("es", "not_found", "test not found"); got != "No encontrado" {
		t.Fatalf("localized code = %q", got)
	}
	if got := ErrorMessage("es", "custom_code", "custom detail"); got != "custom detail" {
		t.Fatalf("custom fallback = %q", got)
	}
}
