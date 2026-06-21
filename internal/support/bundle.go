// SPDX-License-Identifier: LicenseRef-probectl-TBD

package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/version"
)

// maxFileBytes bounds any single bundle file (the topology summary / metrics
// are small; this caps an accidental blow-up). The whole bundle is gzip'd.
const maxFileBytes = 4 << 20 // 4 MiB per file

// TopologySummary is ANONYMIZED deployment shape — counts only, never tenant
// identifiers or telemetry.
type TopologySummary struct {
	Tenants         int            `json:"tenants"`
	Agents          int            `json:"agents"`
	Region          string         `json:"region,omitempty"`
	IsolationModels map[string]int `json:"isolation_models,omitempty"`
	Partial         bool           `json:"partial,omitempty"`
	Errors          []string       `json:"errors,omitempty"`
}

// Runtime is the process's runtime snapshot.
type Runtime struct {
	GoVersion    string `json:"go_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Goroutines   int    `json:"goroutines"`
	MemAllocByte uint64 `json:"mem_alloc_bytes"`
	NumGC        uint32 `json:"num_gc"`
	UptimeSec    int64  `json:"uptime_seconds"`
}

// Sources is everything a bundle includes. All fields are SAFE by
// construction (redacted/anonymized/operational). RedactValues are
// known-sensitive strings (e.g. the envelope key, tokens, DSN passwords) that
// are scrubbed from the assembled bytes as defense in depth.
type Sources struct {
	Version        version.Info
	ConfigRedacted map[string]any
	Health         Health
	SelfMetrics    map[string]float64
	Topology       TopologySummary
	Runtime        Runtime
	Notes          []string
	RedactValues   []string
}

// Manifest indexes the bundle.
type Manifest struct {
	FormatVersion int       `json:"format_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Version       string    `json:"probectl_version"`
	Files         []string  `json:"files"`
	Notes         []string  `json:"notes"`
}

// CollectRuntime snapshots the current process runtime.
func CollectRuntime(startedAt time.Time) Runtime {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Runtime{
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Goroutines:   runtime.NumGoroutine(),
		MemAllocByte: ms.Alloc,
		NumGC:        ms.NumGC,
		UptimeSec:    int64(time.Since(startedAt).Seconds()),
	}
}

// Generate writes a gzip'd tar support bundle to w and returns its manifest.
// Every file is JSON; every file is scrubbed of the caller's known-sensitive
// values before it is written (the no-secrets guarantee). Returns an error
// only on a write failure — the inputs are already safe.
func Generate(w io.Writer, src Sources) (Manifest, error) {
	now := time.Now().UTC()
	man := Manifest{
		FormatVersion: 1,
		GeneratedAt:   now,
		Version:       src.Version.Version,
		Notes: append([]string{
			"This bundle is SECRET-STRIPPED: config is an allowlist with passwords/keys/tokens removed; no tenant telemetry or PII is included.",
		}, src.Notes...),
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	scrub := scrubber(src.RedactValues)
	files := []struct {
		name string
		data any
	}{
		{"version.json", src.Version},
		{"config-redacted.json", src.ConfigRedacted},
		{"health.json", src.Health},
		{"self-metrics.json", src.SelfMetrics},
		{"topology-summary.json", src.Topology},
		{"runtime.json", src.Runtime},
	}
	for _, f := range files {
		raw, err := json.MarshalIndent(f.data, "", "  ")
		if err != nil {
			return man, fmt.Errorf("support: marshal %s: %w", f.name, err)
		}
		raw = scrub(raw)
		if len(raw) > maxFileBytes {
			raw = raw[:maxFileBytes]
		}
		if err := writeTar(tw, f.name, raw, now); err != nil {
			return man, err
		}
		man.Files = append(man.Files, f.name)
	}

	// The manifest goes last so it can list every file.
	man.Files = append(man.Files, "manifest.json")
	mraw, _ := json.MarshalIndent(man, "", "  ")
	if err := writeTar(tw, "manifest.json", scrub(mraw), now); err != nil {
		return man, err
	}

	if err := tw.Close(); err != nil {
		return man, err
	}
	if err := gz.Close(); err != nil {
		return man, err
	}
	return man, nil
}

// scrubber returns a function that replaces every non-trivial known-sensitive
// value with a redaction marker. Short/empty values are skipped (they would
// over-match common tokens like "" or "0").
func scrubber(values []string) func([]byte) []byte {
	var secrets []string
	for _, v := range values {
		if len(v) >= 6 { // avoid scrubbing trivial strings
			secrets = append(secrets, v)
		}
	}
	if len(secrets) == 0 {
		return func(b []byte) []byte { return b }
	}
	return func(b []byte) []byte {
		s := string(b)
		for _, sec := range secrets {
			if strings.Contains(s, sec) {
				s = strings.ReplaceAll(s, sec, "***REDACTED***")
			}
		}
		return []byte(s)
	}
}

func writeTar(tw *tar.Writer, name string, data []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// ReadBundle untars a bundle (tests / tooling): name -> bytes.
func ReadBundle(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil { //nolint:gosec // bounded by maxFileBytes at write time
			return nil, err
		}
		out[hdr.Name] = buf.Bytes()
	}
	return out, nil
}
