package server

import (
	"context"
	"log/slog"

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
	kbs, err := st.ActiveKBArticles(ctx)
	if err != nil {
		slog.Warn("kb download resolve: list active kbs failed", "error", err)
		return
	}
	if len(kbs) == 0 {
		return
	}
	meta, err := st.GetKBMetadataMap(ctx, kbs)
	if err != nil {
		slog.Warn("kb download resolve: metadata failed", "error", err)
		return
	}
	resolved := 0
	for _, kb := range kbs {
		m := meta[kb]
		if m.ProductFamily != "windows" || m.DownloadURL != "" {
			continue
		}
		info, err := resolver.Resolve(ctx, kb, "", "x64")
		if err != nil {
			slog.Debug("kb download resolve failed", "kb", kb, "error", err)
			continue
		}
		if err := st.SetKBDownloadInfo(ctx, kb, info.URL, info.SHA256); err != nil {
			slog.Warn("kb download resolve: persist failed", "kb", kb, "error", err)
			continue
		}
		resolved++
	}
	if resolved > 0 {
		slog.Info("kb download resolve completed", "resolved", resolved)
	}
}
