// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import "testing"

func TestSurfaceCatalogIgnoresCommentedAndStringDecoys(t *testing.T) {
	const source = `
const stringDecoy = "export const SURFACES = [{ featureIds: ['F-STRING'], kind: 'native', route: '/string' }]"
// export const SURFACES = [{ featureIds: ['F-LINE'], kind: 'native', route: '/line' }]
/*
export const SURFACES = [{ featureIds: ['F-BLOCK'], kind: 'native', route: '/block' }]
*/
export const SURFACES: SurfaceDecl[] = [
  {
    capability: "decoy prose: featureIds: ['F-PROSE'], kind: 'native', route: '/prose'",
    featureIds: ['F1', 'F2'],
    kind: 'native',
    route: '/real',
  },
]
`
	declarations, err := parseSurfaceCatalog([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	validator := &Validator{surfaces: declarations}
	for _, tc := range []struct {
		feature string
		route   string
		want    bool
	}{
		{feature: "F1", route: "/real", want: true},
		{feature: "F2", route: "/real", want: true},
		{feature: "F-STRING", route: "/string", want: false},
		{feature: "F-LINE", route: "/line", want: false},
		{feature: "F-BLOCK", route: "/block", want: false},
		{feature: "F-PROSE", route: "/prose", want: false},
	} {
		if got := validator.surfaceExists(tc.feature, tc.route); got != tc.want {
			t.Errorf("surfaceExists(%q, %q) = %v, want %v", tc.feature, tc.route, got, tc.want)
		}
	}
}

func TestSurfaceExistsRequiresExactNativeDeclaration(t *testing.T) {
	const source = `
export const SURFACES = [
  { featureIds: ['F-NATIVE'], kind: 'native', route: '/native' },
  { featureIds: ['F-FEDERATED'], kind: 'federated', evidence: ['openapi:/v1/example'] },
  { featureIds: ['F-NONE'], kind: 'none-by-design', noneReason: 'Deliberate.' },
]
`
	declarations, err := parseSurfaceCatalog([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	validator := &Validator{surfaces: declarations}
	if !validator.surfaceExists("F-NATIVE", "/native") {
		t.Fatal("exact native feature and route were not found")
	}
	if validator.surfaceExists("F-NATIVE", "/native/child") {
		t.Fatal("route prefix was accepted instead of an exact route")
	}
	if validator.surfaceExists("F-FEDERATED", "/native") {
		t.Fatal("federated evidence was accepted as a native route")
	}
	if validator.surfaceExists("F-NONE", "/native") {
		t.Fatal("none-by-design evidence was accepted as a native route")
	}
}

func TestSurfaceCatalogFailsClosedOnDynamicEvidenceFields(t *testing.T) {
	for _, source := range []string{
		`export const SURFACES = [{ featureIds: computedIDs, kind: 'native', route: '/x' }]`,
		`export const SURFACES = [{ featureIds: ['F1'], kind: getKind(), route: '/x' }]`,
		`export const SURFACES = [{ featureIds: ['F1'], kind: 'native', route: getRoute() }]`,
		`export const SURFACES = [...factory([{ featureIds: ['F1'], kind: 'native', route: '/nested' }])]`,
		`export const SURFACES = [{ featureIds: ['F1'], kind: 'native', route: '/x', ...{ featureIds: [] } }]`,
		`export const SURFACES = [{ featureIds: ['F1'], kind: 'native', route: '/x', ['featureIds']: [] }]`,
	} {
		if _, err := parseSurfaceCatalog([]byte(source)); err == nil {
			t.Fatalf("dynamic evidence field was accepted: %s", source)
		}
	}
}
