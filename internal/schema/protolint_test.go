// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package schema holds offline schema-hygiene lints (SCHEMA-006). It is
// test-only: there is no production code here, just guards that read the
// committed .proto sources and fail the build on a policy violation.
package schema

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestProtoNoUnreservedTagGaps: SCHEMA-006. First-party messages are
// append-only; when a field is removed its NUMBER must be fenced with a
// `reserved` clause so the tag can never be silently reused. This lint walks the
// committed first-party protos and fails if a message's field-number sequence
// has a gap (a missing number below its max) that no `reserved` entry covers.
//
// It is a heuristic line scanner (not a full proto parser) — deliberately
// conservative: it only considers top-level `<type> name = N;` field lines and
// `reserved` number lists/ranges, which is exactly the shape our schemas use.
func TestProtoNoUnreservedTagGaps(t *testing.T) {
	root := firstPartyProtoRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".proto") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no first-party protos found under %s", root)
	}
	for _, f := range files {
		checkProtoFile(t, f)
	}
}

func firstPartyProtoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the package dir to the repo root, then into proto/probectl.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		cand := filepath.Join(dir, "proto", "probectl")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate proto/probectl from the test working directory")
	return ""
}

var (
	reMsgOpen  = regexp.MustCompile(`^\s*message\s+(\w+)\s*\{`)
	reField    = regexp.MustCompile(`^\s*(?:repeated\s+|optional\s+)?[\w.<>, ]+\s+\w+\s*=\s*(\d+)\s*;`)
	reReserved = regexp.MustCompile(`^\s*reserved\s+(.+);`)
	reNumRange = regexp.MustCompile(`(\d+)\s+to\s+(\d+)`)
)

func checkProtoFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")

	type msgState struct {
		name     string
		nums     map[int]bool
		reserved map[int]bool
		depth    int
	}
	var stack []*msgState

	for _, raw := range lines {
		line := stripLineComment(raw)
		if m := reMsgOpen.FindStringSubmatch(line); m != nil {
			stack = append(stack, &msgState{name: m[1], nums: map[int]bool{}, reserved: map[int]bool{}, depth: 1})
			continue
		}
		if len(stack) == 0 {
			continue
		}
		cur := stack[len(stack)-1]
		// Track nesting so a field belongs to the innermost message.
		cur.depth += strings.Count(line, "{") - strings.Count(line, "}")
		if cur.depth <= 0 {
			finishMsg(t, path, cur.name, cur.nums, cur.reserved)
			stack = stack[:len(stack)-1]
			continue
		}
		if m := reReserved.FindStringSubmatch(line); m != nil {
			parseReserved(m[1], cur.reserved)
			continue
		}
		if m := reField.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				cur.nums[n] = true
			}
		}
	}
}

func finishMsg(t *testing.T, path, name string, nums, reserved map[int]bool) {
	if len(nums) == 0 {
		return
	}
	keys := make([]int, 0, len(nums))
	max := 0
	for n := range nums {
		keys = append(keys, n)
		if n > max {
			max = n
		}
	}
	sort.Ints(keys)
	for n := 1; n <= max; n++ {
		if !nums[n] && !reserved[n] {
			t.Errorf("%s message %s: field number %d is missing (a gap) and not covered by a `reserved` clause — a retired tag MUST be reserved so it is never reused (SCHEMA-006)", filepath.Base(path), name, n)
		}
	}
}

func parseReserved(body string, into map[int]bool) {
	// Strip string names (reserved "old"); only numbers matter for gap coverage.
	for _, rng := range reNumRange.FindAllStringSubmatch(body, -1) {
		a, _ := strconv.Atoi(rng[1])
		b, _ := strconv.Atoi(rng[2])
		for n := a; n <= b; n++ {
			into[n] = true
		}
	}
	bodyNoRanges := reNumRange.ReplaceAllString(body, "")
	for _, tok := range strings.FieldsFunc(bodyNoRanges, func(r rune) bool { return r == ',' || r == ' ' }) {
		if n, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			into[n] = true
		}
	}
}

func stripLineComment(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		return s[:i]
	}
	return s
}
