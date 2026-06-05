//go:build probectl_fips

package crypto

// fipsBuildTag is true in the FIPS distribution artifact (built with
// -tags probectl_fips). It is the DISTRIBUTION marker — the editions
// decision: the FIPS build is gated by the artifact, never a runtime license
// check. Activating the validated module itself is orthogonal (GOFIPS140 at
// build time, or GODEBUG=fips140=on at runtime); the power-on self-test
// asserts the module is actually live in this build and fails closed if not.
const fipsBuildTag = true
