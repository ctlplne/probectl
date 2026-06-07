package canary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RED-008: the ca_file probe parameter is contained to the allowlisted
// directory — traversal, absolute escapes, and symlink escapes are refused;
// with no directory configured the parameter is refused outright.
func TestCAFileContainment(t *testing.T) {
	t.Cleanup(func() { SetCAFileDir("") })

	root := t.TempDir()
	caDir := filepath.Join(root, "ca.d")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(caDir, "corp-ca.pem")
	if err := os.WriteFile(inside, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "etc-shadow")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink INSIDE the dir pointing OUTSIDE must be refused too.
	link := filepath.Join(caDir, "sneaky.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// Default: no allowlisted dir → ca_file refused entirely (fail closed).
	SetCAFileDir("")
	if _, err := ResolveCAFile("corp-ca.pem"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("unset dir must refuse ca_file, got %v", err)
	}

	SetCAFileDir(caDir)
	cases := []struct {
		name, p string
		ok      bool
	}{
		{"relative inside", "corp-ca.pem", true},
		{"absolute inside", inside, true},
		{"traversal", "../etc-shadow", false},
		{"deep traversal", "a/../../etc-shadow", false},
		{"absolute outside", outside, false},
		{"symlink escape", "sneaky.pem", false},
		{"symlink escape absolute", link, false},
		{"missing file", "nope.pem", false},
	}
	for _, tc := range cases {
		got, err := ResolveCAFile(tc.p)
		if tc.ok && err != nil {
			t.Errorf("%s: want allowed, got %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: ESCAPED containment → %s", tc.name, got)
		}
	}
}
