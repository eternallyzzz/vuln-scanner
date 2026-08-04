package server

import (
	"regexp"
	"strings"

	"vuln-scanner/internal/store"
)

var kbInURLLink = regexp.MustCompile(`KB(\d+)`)

// msrcLinks returns the MSRC Update Guide link for a CVE or ADV advisory
// (stable and always resolvable) plus a support.microsoft.com help page for
// the KB. The catalog search page is not used because it does not render
// results for direct links.
func msrcLinks(cveID, storedURL string) (advisoryURL, patchURL string) {
	switch {
	case strings.HasPrefix(cveID, "CVE-"):
		advisoryURL = "https://msrc.microsoft.com/update-guide/vulnerability/" + cveID
	case strings.HasPrefix(cveID, "ADV"):
		advisoryURL = "https://msrc.microsoft.com/update-guide/advisory/" + cveID
	default:
		advisoryURL = storedURL
	}
	if m := kbInURLLink.FindStringSubmatch(storedURL); m != nil {
		patchURL = "https://support.microsoft.com/help/" + m[1]
	}
	return advisoryURL, patchURL
}

// enrichAdvisoryURLs adds the MSRC Update Guide link to msrc vulnerability
// rows for API responses.
func enrichAdvisoryURLs(results []store.CVEResult) {
	for i := range results {
		if results[i].Source != "msrc" {
			continue
		}
		switch {
		case strings.HasPrefix(results[i].CVEID, "CVE-"):
			results[i].AdvisoryURL = "https://msrc.microsoft.com/update-guide/vulnerability/" + results[i].CVEID
		case strings.HasPrefix(results[i].CVEID, "ADV"):
			results[i].AdvisoryURL = "https://msrc.microsoft.com/update-guide/advisory/" + results[i].CVEID
		}
	}
}

// enrichKBLinks fills per-KB reference and patch links for KB recommendations:
// the reference points to the Update Guide of the first CVE, the patch link to
// the support.microsoft.com help page of the KB.
func enrichKBLinks(kbs []store.KBPatchRecommendation) {
	for i := range kbs {
		cveID := ""
		if len(kbs[i].CVEIDs) > 0 {
			cveID = kbs[i].CVEIDs[0]
		}
		ref, patch := msrcLinks(cveID, kbs[i].Kb)
		if cveID == "" {
			ref = ""
		}
		kbs[i].ReferenceURL = ref
		kbs[i].PatchURL = patch
	}
}
