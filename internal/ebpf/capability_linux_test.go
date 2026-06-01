//go:build linux

package ebpf

import "testing"

func TestKernelAtLeast(t *testing.T) {
	cases := []struct {
		rel      string
		maj, min int
		want     bool
	}{
		{"6.8.0-106-generic", 5, 8, true},
		{"5.8.0", 5, 8, true},
		{"5.7.19", 5, 8, false},
		{"4.19.0-26-amd64", 5, 8, false},
		{"6.1.0", 5, 8, true},
		{"garbage", 5, 8, false},
	}
	for _, c := range cases {
		if got := kernelAtLeast(c.rel, c.maj, c.min); got != c.want {
			t.Errorf("kernelAtLeast(%q,%d,%d) = %v, want %v", c.rel, c.maj, c.min, got, c.want)
		}
	}
}

func TestDigitPrefix(t *testing.T) {
	for in, want := range map[string]string{"106-generic": "106", "8": "8", "x": "", "0rc1": "0"} {
		if got := digitPrefix(in); got != want {
			t.Errorf("digitPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
