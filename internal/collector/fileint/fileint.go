// Package fileint collects periodic file-integrity facts (SHA256, size,
// mode, mtime) for a bounded, operator-configured set of sensitive paths.
// It is intentionally not a real-time file watcher: the server diffs the
// periodic snapshots against a baseline.
package fileint

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FileFact is one file's integrity state.
type FileFact struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	Mode       string `json:"mode"`
	ModifiedAt string `json:"modified_at"`
}

// Config bounds the collection work so a misconfigured path can never make
// the agent scan the whole disk or stall on huge files.
type Config struct {
	MaxFileBytes   int64
	MaxFilesPerDir int
}

// DefaultConfig returns 64 MiB per file and 200 direct files per directory.
func DefaultConfig() Config {
	return Config{MaxFileBytes: 64 << 20, MaxFilesPerDir: 200}
}

// DefaultPaths returns the built-in high-risk path list for the current OS.
// These are conservative: configuration/identity/cron/startup locations that
// are cheap to hash and highly sensitive when tampered with.
func DefaultPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\drivers\etc\networks`,
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\config\SYSTEM`,
			`C:\Windows\System32\config\SOFTWARE`,
			`C:\Windows\System32\config\SECURITY`,
		}
	}
	return []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/ssh/sshd_config",
		"/root/.ssh/authorized_keys",
		"/home/.ssh/authorized_keys",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/systemd/system",
		"/usr/local/bin",
	}
}

// Collect hashes every configured file/directory and returns deterministic,
// deduplicated facts. Directories contribute their direct regular-file
// children only (no recursion), bounded by MaxFilesPerDir; symlinks are
// skipped to avoid following attacker-controlled links.
func Collect(ctx context.Context, paths []string, cfg Config) ([]FileFact, error) {
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = DefaultConfig().MaxFileBytes
	}
	if cfg.MaxFilesPerDir <= 0 {
		cfg.MaxFilesPerDir = DefaultConfig().MaxFilesPerDir
	}
	seen := make(map[string]bool)
	var out []FileFact
	var scanErrs []string
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		facts, err := collectPath(ctx, p, cfg)
		if err != nil {
			scanErrs = append(scanErrs, err.Error())
			continue
		}
		for _, f := range facts {
			key := strings.ToLower(filepath.Clean(f.Path))
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(scanErrs) > 0 {
		return out, fmt.Errorf("file integrity scan: %s", strings.Join(scanErrs, "; "))
	}
	return out, nil
}

func collectPath(ctx context.Context, p string, cfg Config) ([]FileFact, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	if !info.IsDir() {
		f, err := hashFile(ctx, p, cfg.MaxFileBytes)
		if err != nil {
			return nil, err
		}
		return []FileFact{f}, nil
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	if len(entries) > cfg.MaxFilesPerDir {
		slog.Warn("fileint: directory truncated", "path", p, "entries", len(entries), "max", cfg.MaxFilesPerDir)
		entries = entries[:cfg.MaxFilesPerDir]
	}
	var out []FileFact
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		child := filepath.Join(p, e.Name())
		f, err := hashFile(ctx, child, cfg.MaxFileBytes)
		if err != nil {
			slog.Debug("fileint: skip child", "path", child, "error", err)
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func hashFile(ctx context.Context, path string, maxBytes int64) (FileFact, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileFact{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return FileFact{}, err
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return FileFact{}, fmt.Errorf("%s exceeds max file size", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return FileFact{}, err
	}
	return FileFact{
		Path:       filepath.Clean(path),
		SHA256:     fmt.Sprintf("%x", h.Sum(nil)),
		SizeBytes:  info.Size(),
		Mode:       fmt.Sprintf("%04o", info.Mode().Perm()),
		ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}
