package crypto

import (
	"encoding/hex"
	"testing"
)

func TestHashKnownVector(t *testing.T) {
	// SHA-256 of the empty string.
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(Hash(nil)); got != empty {
		t.Errorf("Hash(nil) = %s, want %s", got, empty)
	}
}

func TestHashDeterministicAndDistinct(t *testing.T) {
	a1 := hex.EncodeToString(Hash([]byte("probectl")))
	a2 := hex.EncodeToString(Hash([]byte("probectl")))
	b := hex.EncodeToString(Hash([]byte("netct1")))
	if a1 != a2 {
		t.Error("Hash is not deterministic")
	}
	if a1 == b {
		t.Error("Hash collided on distinct inputs")
	}
	if len(Hash(nil)) != 32 {
		t.Errorf("digest length = %d, want 32", len(Hash(nil)))
	}
}
