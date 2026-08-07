package server

import (
	"context"
	"fmt"
	"strings"

	"vuln-scanner/internal/store"
)

// advisoryURLFor returns the stable MSRC Update Guide URL for a CVE or ADV
// advisory; unknown ID formats keep the stored URL.
func advisoryURLFor(cveID, storedURL string) string {
	switch {
	case strings.HasPrefix(cveID, "CVE-"):
		return "https://msrc.microsoft.com/update-guide/vulnerability/" + cveID
	case strings.HasPrefix(cveID, "ADV"):
		return "https://msrc.microsoft.com/update-guide/advisory/" + cveID
	default:
		return storedURL
	}
}

// catalogURLForKB builds the Update Catalog search link for a KB article.
func catalogURLForKB(kb string) string {
	digits := 0
	for _, c := range kb {
		if c >= '0' && c <= '9' {
			digits = digits*10 + int(c-'0')
		}
	}
	if digits == 0 {
		return ""
	}
	return fmt.Sprintf("https://www.catalog.update.microsoft.com/Search.aspx?q=KB%d", digits)
}

// enrichAdvisoryURLs adds the MSRC Update Guide link to msrc vulnerability
// rows for API responses.
func enrichAdvisoryURLs(results []store.CVEResult) {
	for i := range results {
		if results[i].Source != "msrc" {
			continue
		}
		results[i].AdvisoryURL = advisoryURLFor(results[i].CVEID, results[i].KBURL)
	}
}

// enrichKBLinks fills per-KB links from kb_metadata and per-agent download
// rows: an MSRC Update Guide reference, the verified support.microsoft.com
// help page when available, the exact OS/arch direct download, and the
// Update Catalog search link as fallback.
func enrichKBLinks(kbs []store.KBPatchRecommendation, meta map[string]store.KBMetadata,
	downloads map[string][]store.KBDownload, agentOS, agentArch string) {
	for i := range kbs {
		cveID := ""
		if len(kbs[i].CVEIDs) > 0 {
			cveID = kbs[i].CVEIDs[0]
		}
		adv := advisoryURLFor(cveID, "")
		if cveID == "" {
			adv = ""
		}
		kbs[i].ReferenceURL = adv

		m := meta[kbs[i].Kb]
		dl := selectKBDownload(downloads[kbs[i].Kb], kbOSFamily(agentOS), agentArch)
		kbs[i].Links = nil
		if adv != "" {
			kbs[i].Links = append(kbs[i].Links, store.PatchLink{
				Type: "advisory", URL: adv, Verified: true,
			})
		}
		if m.SupportURL != "" {
			kbs[i].Links = append(kbs[i].Links, store.PatchLink{
				Type: "support", URL: m.SupportURL, Verified: m.Status == "ok",
			})
		}
		if dl != nil && dl.URL != "" {
			kbs[i].Links = append(kbs[i].Links, store.PatchLink{
				Type: "download", URL: dl.URL, Verified: dl.SHA256 != "",
			})
		}
		catalog := m.CatalogURL
		if catalog == "" {
			catalog = catalogURLForKB(kbs[i].Kb)
		}
		if catalog != "" {
			kbs[i].Links = append(kbs[i].Links, store.PatchLink{
				Type: "catalog", URL: catalog,
			})
		}
		kbs[i].PatchURL = bestPatchURL(m, downloads[kbs[i].Kb], agentOS, agentArch)
		if dl != nil {
			kbs[i].PatchSHA256 = dl.SHA256
		}
		if kbs[i].PatchURL == "" {
			kbs[i].PatchURL = catalog
		}
	}
}

// bestPatchURL picks the most actionable patch link: an exact OS/arch direct
// download with a SHA256 first, then a verified support page, then the Update
// Catalog search link. A download without a usable SHA256 is shown as an
// unverified link but is never auto-deployable; the legacy kb_metadata
// download fields are intentionally ignored after migration 047.
func bestPatchURL(m store.KBMetadata, downloads []store.KBDownload, agentOS, agentArch string) string {
	if dl := selectVerifiedKBDownload(downloads, kbOSFamily(agentOS), agentArch); dl != nil && dl.URL != "" {
		return dl.URL
	}
	if m.Status == "ok" && m.SupportURL != "" {
		return m.SupportURL
	}
	if m.CatalogURL != "" {
		return m.CatalogURL
	}
	return m.SupportURL
}

// selectVerifiedKBDownload narrows downloads to rows with a usable SHA256
// before choosing the best OS/arch match, so only hash-verified downloads
// can become auto-deployable.
func selectVerifiedKBDownload(downloads []store.KBDownload, osFamily, arch string) *store.KBDownload {
	verified := make([]store.KBDownload, 0, len(downloads))
	for _, d := range downloads {
		if d.SHA256 != "" {
			verified = append(verified, d)
		}
	}
	return selectKBDownload(verified, osFamily, arch)
}

// kbOSFamily maps an agent OS string to the Windows family token used by the
// Update Catalog selection and kb_downloads rows.
func kbOSFamily(osType string) string {
	lower := strings.ToLower(osType)
	switch {
	case strings.Contains(lower, "windows 11"):
		return "windows 11"
	case strings.Contains(lower, "windows 10"):
		return "windows 10"
	case strings.Contains(lower, "server"):
		return "server"
	default:
		return ""
	}
}

// selectKBDownload picks the direct download that best matches the agent OS
// family and architecture: exact family+arch, then arch-only, then
// family-only, then the first deterministic row.
func selectKBDownload(downloads []store.KBDownload, osFamily, arch string) *store.KBDownload {
	if len(downloads) == 0 {
		return nil
	}
	archTok := "x64"
	lowerArch := strings.ToLower(arch)
	if strings.Contains(lowerArch, "arm") || strings.Contains(lowerArch, "aarch64") {
		archTok = "arm64"
	}
	for i := range downloads {
		if downloads[i].OSFamily == osFamily && downloads[i].Arch == archTok {
			return &downloads[i]
		}
	}
	for i := range downloads {
		if downloads[i].OSFamily == "" && downloads[i].Arch == archTok {
			return &downloads[i]
		}
	}
	for i := range downloads {
		if downloads[i].OSFamily == osFamily && downloads[i].Arch == "" {
			return &downloads[i]
		}
	}
	return &downloads[0]
}

// loadKBMetadata loads link metadata for every KB referenced by the
// recommendations in one query.
func loadKBMetadata(ctx context.Context, st *store.Store, recs []store.FixRecommendation) map[string]store.KBMetadata {
	var kbs []string
	seen := make(map[string]bool)
	for _, r := range recs {
		for _, k := range r.KBs {
			if k.Kb != "" && !seen[k.Kb] {
				seen[k.Kb] = true
				kbs = append(kbs, k.Kb)
			}
		}
	}
	if len(kbs) == 0 {
		return nil
	}
	m, err := st.GetKBMetadataMap(ctx, kbs)
	if err != nil {
		return nil
	}
	return m
}

// loadKBDownloads loads per-KB/OS/arch download rows for every KB referenced
// by the recommendations.
func loadKBDownloads(ctx context.Context, st *store.Store, recs []store.FixRecommendation) map[string][]store.KBDownload {
	var kbs []string
	seen := make(map[string]bool)
	for _, r := range recs {
		for _, k := range r.KBs {
			if k.Kb != "" && !seen[k.Kb] {
				seen[k.Kb] = true
				kbs = append(kbs, k.Kb)
			}
		}
	}
	if len(kbs) == 0 {
		return nil
	}
	m, err := st.GetKBDownloads(ctx, kbs)
	if err != nil {
		return nil
	}
	return m
}
