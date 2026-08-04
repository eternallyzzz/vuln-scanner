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

// enrichKBLinks fills per-KB links from kb_metadata: an MSRC Update Guide
// reference, the verified support.microsoft.com help page when available, and
// the Update Catalog search link as fallback.
func enrichKBLinks(kbs []store.KBPatchRecommendation, meta map[string]store.KBMetadata) {
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
		if m.DownloadURL != "" {
			kbs[i].Links = append(kbs[i].Links, store.PatchLink{
				Type: "download", URL: m.DownloadURL, Verified: m.DownloadSHA256 != "",
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
		kbs[i].PatchURL = bestPatchURL(m)
		if kbs[i].PatchURL == "" {
			kbs[i].PatchURL = catalog
		}
	}
}

// bestPatchURL picks the most actionable patch link: a resolved direct
// download first, then a verified support page, then the Update Catalog
// search link.
func bestPatchURL(m store.KBMetadata) string {
	if m.DownloadURL != "" {
		return m.DownloadURL
	}
	if m.Status == "ok" && m.SupportURL != "" {
		return m.SupportURL
	}
	if m.CatalogURL != "" {
		return m.CatalogURL
	}
	return m.SupportURL
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
