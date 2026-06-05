//go:build !probectl_fips

package crypto

// fipsBuildTag is false in the standard (non-FIPS) build. The power-on
// self-test still runs its known-answer tests here (good hygiene, and it
// proves the S3 interface produces identical, standardized outputs whether or
// not FIPS is compiled in — the transparent-swap property), but it does not
// require the validated module to be active.
const fipsBuildTag = false
