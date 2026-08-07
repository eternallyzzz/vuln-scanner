package server

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

// resolveActiveKBDownloads resolves direct .msu download links for the KBs
// currently referenced by active vulnerability results. Failures are
// non-fatal: the recommendation stays usable with the catalog search link.
func resolveActiveKBDownloads(ctx context.Context, st *store.Store, resolver *patch.CatalogResolver) {
	if resolver == nil {
		return
	}
	targets, err := st.ActiveKBDownloadTargets(ctx)
	if err != nil {
		slog.Warn("kb download resolve: list active targets failed", "error", err)
		return
	}
	if len(targets) == 0 {
		return
	}
	resolved := 0
	seen := make(map[string]bool)
	for _, target := range targets {
		key := target.KB + "|" + kbOSFamily(target.OSType) + "|" + target.Arch
		if seen[key] {
			continue
		}
		seen[key] = true
		family := kbOSFamily(target.OSType)
		existing, err := st.GetKBDownloads(ctx, []string{target.KB})
		if err != nil {
			slog.Warn("kb download resolve: metadata failed", "kb", target.KB, "error", err)
			continue
		}
		if dl := selectKBDownload(existing[target.KB], family, target.Arch); dl != nil &&
			dl.VerifiedAt != nil && time.Since(*dl.VerifiedAt) < 24*time.Hour {
			continue
		}
		info, err := resolver.Resolve(ctx, target.KB, target.OSType, target.Arch)
		if err != nil {
			slog.Debug("kb download resolve failed", "kb", target.KB, "error", err)
			continue
		}
		if err := st.SetKBDownload(ctx, store.KBDownload{
			KB: target.KB, OSFamily: family, Arch: normalizeDownloadArch(target.Arch),
			Title: info.Title, URL: info.URL, SHA256: info.SHA256,
		}); err != nil {
			slog.Warn("kb download resolve: persist failed", "kb", target.KB, "error", err)
			continue
		}
		resolved++
	}
	if resolved > 0 {
		slog.Info("kb download resolve completed", "resolved", resolved)
	}
}

func normalizeDownloadArch(arch string) string {
	if arch == "" {
		return "x64"
	}
	lower := strings.ToLower(arch)
	if strings.HasPrefix(lower, "arm") || strings.HasPrefix(lower, "aarch64") {
		return "arm64"
	}
	return "x64"
}
