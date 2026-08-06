package store

import (
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "vsk_") || len(key) < 20 {
		t.Fatalf("generated key %q does not look like an API key", key)
	}
	other, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == other {
		t.Fatal("two generated keys must not collide")
	}
}

func TestHashAPIKey(t *testing.T) {
	key := "vsk_test-key-value"
	h1 := HashAPIKey(key)
	h2 := HashAPIKey(key)
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash must be stable SHA-256 hex, got %q and %q", h1, h2)
	}
	if HashAPIKey(key+"x") == h1 {
		t.Fatal("different keys must hash differently")
	}
	if strings.Contains(h1, key) {
		t.Fatal("hash must not embed the plaintext key")
	}
}
