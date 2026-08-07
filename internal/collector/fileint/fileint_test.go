package fileint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectHashesFilesAndSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "hosts")
	if err := os.WriteFile(file, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err == nil {
		defer os.Remove(link)
	}

	facts, err := Collect(context.Background(), []string{dir}, DefaultConfig())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("facts = %d, want 1 (only direct file hosts; subdir and symlink skipped)", len(facts))
	}
	byPath := map[string]FileFact{}
	for _, f := range facts {
		byPath[f.Path] = f
	}
	if f := byPath[file]; f.SHA256 == "" || f.SizeBytes == 0 || f.Mode == "" {
		t.Fatalf("hosts fact = %+v", f)
	}
	if _, ok := byPath[link]; ok {
		t.Fatal("symlink must be skipped")
	}
}

func TestCollectMaxFileBytes(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.MaxFileBytes = 1024
	_, err := Collect(context.Background(), []string{big}, cfg)
	if err == nil {
		t.Fatal("oversized file must produce a scan error")
	}
	facts, err := Collect(context.Background(), []string{dir}, cfg)
	if err != nil {
		t.Fatalf("directory scan with oversized child must skip it, got error: %v", err)
	}
	if len(facts) != 0 {
		t.Fatalf("facts = %d, want 0 (oversized child skipped)", len(facts))
	}
}

func TestCollectMaxFilesPerDir(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+string(rune('a'+i))), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultConfig()
	cfg.MaxFilesPerDir = 3
	facts, err := Collect(context.Background(), []string{dir}, cfg)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(facts) != 3 {
		t.Fatalf("facts = %d, want 3 (truncated)", len(facts))
	}
}
