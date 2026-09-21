// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package version exposes build metadata shared by every probectl binary.
//
// The Version, Commit, and Date values are injected at build time via
// -ldflags (see LDFLAGS in the Makefile). When built without ldflags
// (for example `go run ./cmd/probectl-control`), they fall back to the
// development defaults below.
package version

import (
	"fmt"
	"runtime"
	"strings"
)

// Build metadata. These are overridden at link time with
// -ldflags "-X github.com/ctlplne/probectl/internal/version.Version=...".
var (
	// Version is the semantic version of the build (e.g. "v0.1.0").
	Version = "0.0.0-dev"
	// Commit is the (short) git SHA the build was produced from.
	Commit = "unknown"
	// Date is the build timestamp in RFC 3339 form.
	Date = "unknown"
)

// Modified reports whether Commit describes the source this binary was actually
// built from. A build produced from a working tree with uncommitted changes
// carries a "-dirty" suffix by convention (see the Makefile), and anything that
// asserts provenance — the metrics endpoint, the signed auditor bundle — has to
// treat that as "not a released build" rather than quoting the SHA as if it
// identified the artifact (DPR-148). An "unknown" commit is equally unusable.
func (i Info) Modified() bool {
	return strings.HasSuffix(i.Commit, "-dirty")
}

// ProvenanceTrustworthy reports whether Commit identifies a real, unmodified
// source revision. False means the binary cannot be traced to a published
// artifact, and a document that says otherwise would be wrong.
func (i Info) ProvenanceTrustworthy() bool {
	c := strings.TrimSpace(i.Commit)
	return c != "" && c != "unknown" && !strings.HasSuffix(c, "-dirty")
}

// Info is a structured snapshot of the build metadata plus the runtime
// environment the binary is executing in.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String renders the build metadata as a single human-readable line.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}
