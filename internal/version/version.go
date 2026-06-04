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
)

// Build metadata. These are overridden at link time with
// -ldflags "-X github.com/imfeelingtheagi/probectl/internal/version.Version=...".
var (
	// Version is the semantic version of the build (e.g. "v0.1.0").
	Version = "0.0.0-dev"
	// Commit is the (short) git SHA the build was produced from.
	Commit = "unknown"
	// Date is the build timestamp in RFC 3339 form.
	Date = "unknown"
)

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
