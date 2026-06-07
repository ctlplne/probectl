package canary

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// ca_file containment (Sprint 12, RED-008): probe specs arrive over the API,
// so the ca_file parameter must never become an arbitrary-path read primitive
// on the agent host. The agent runtime allowlists ONE directory
// (tls.canary_ca_dir / PROBECTL_AGENT_CANARY_CA_DIR); every ca_file must
// resolve inside it — symlinks included — or the probe refuses to construct.
// With no directory configured, ca_file is refused entirely (fail closed).

var (
	caDirMu sync.RWMutex
	caDir   string
)

// SetCAFileDir installs the allowlisted anchor directory ("" = ca_file refused).
func SetCAFileDir(dir string) {
	caDirMu.Lock()
	defer caDirMu.Unlock()
	caDir = dir
}

// ResolveCAFile validates p against the allowlisted directory and returns the
// path to read. Traversal ("..", absolute escapes) and symlink escapes are
// refused; relative paths resolve inside the allowlisted dir.
func ResolveCAFile(p string) (string, error) {
	caDirMu.RLock()
	dir := caDir
	caDirMu.RUnlock()
	if dir == "" {
		return "", fmt.Errorf("canary: ca_file is disabled on this agent (set tls.canary_ca_dir to allowlist a CA directory — RED-008)")
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	// Resolve the ALLOWLISTED root through symlinks once, so containment is
	// judged in real-path space.
	if real, err := filepath.EvalSymlinks(dirAbs); err == nil {
		dirAbs = real
	}
	cand := p
	if !filepath.IsAbs(cand) {
		cand = filepath.Join(dirAbs, cand)
	}
	cand = filepath.Clean(cand)
	// The candidate must exist and resolve (symlinks included) INSIDE the dir.
	real, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", fmt.Errorf("canary: ca_file %q: %v", p, err)
	}
	if real != dirAbs && !strings.HasPrefix(real, dirAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("canary: ca_file %q escapes the allowlisted CA directory (RED-008)", p)
	}
	return real, nil
}
