package cve

import (
	"strconv"
	"strings"

	"vuln-scanner/internal/collector"
)

// parseWindowsFullBuild extracts the Windows build number and optional UBR
// revision from a version string such as "10.0.22621.3007",
// "6.3.22621.3007" or "22621.674". hasRevision is false when only a build is
// present.
func parseWindowsFullBuild(version string) (build, revision int, hasRevision, ok bool) {
	var nums []int
	for _, part := range strings.Split(version, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	for i := len(nums) - 1; i >= 0; i-- {
		if nums[i] >= 10000 {
			if i+1 < len(nums) {
				return nums[i], nums[i+1], true, true
			}
			return nums[i], 0, false, true
		}
	}
	return 0, 0, false, false
}

// msrcOSFixedByBuild reports whether the agent's full build/revision is at
// least the MSRC fixed CPE version. A larger build is fixed; equal builds are
// compared by revision. When either side has no revision, only the build is
// compared and equal builds are treated as not fixed (the pre-existing
// behavior).
func msrcOSFixedByBuild(agentVersion, fixedCPEVer string) bool {
	agentBuild, agentRev, agentHasRev, agentOK := parseWindowsFullBuild(agentVersion)
	fixedBuild, fixedRev, fixedHasRev, fixedOK := parseWindowsFullBuild(fixedCPEVer)
	if !agentOK || !fixedOK || fixedBuild == 0 {
		return false
	}
	if agentBuild != fixedBuild {
		return agentBuild > fixedBuild
	}
	if agentHasRev && fixedHasRev {
		return agentRev >= fixedRev
	}
	return false
}

// applyWUAVerification reconciles local inference results with authoritative
// WUA/WSUS facts. With a reachable update source, a pending fact for the
// CVE's KB marks it active, and an installed fact marks it fixed. When the
// source is unreachable or there is no fact for the KB, the local result is
// kept and labelled "local".
func applyWUAVerification(results []MatchedCVE, facts []collector.UpdateFact,
	status *collector.UpdateSourceStatus) []MatchedCVE {
	if status == nil || !status.SourceReachable {
		for i := range results {
			if results[i].VerificationSource == "" {
				results[i].VerificationSource = "local"
			}
		}
		return results
	}

	pending := make(map[string]string)
	installed := make(map[string]bool)
	installedSource := make(map[string]string)
	for _, f := range facts {
		kb := normalizeKBKey(f.KB)
		if kb == "" {
			continue
		}
		label := "wua"
		if f.Source == "wsus" {
			label = "wsus"
		}
		if f.State == "installed" {
			installed[kb] = true
			installedSource[kb] = label
		} else {
			pending[kb] = label
		}
	}

	for i := range results {
		r := &results[i]
		if r.VerificationSource == "" {
			r.VerificationSource = "local"
		}
		if r.Source != "msrc" || r.KBArticle == "" {
			continue
		}
		kb := normalizeKBKey(r.KBArticle)
		if kb == "" {
			continue
		}
		if label, ok := pending[kb]; ok {
			r.MatchStatus = "active"
			if r.FixedVersion == "" {
				r.FixedVersion = r.KBArticle
			}
			r.VerificationSource = label
			continue
		}
		if installed[kb] || isKBFixed(r.KBArticle, installed) {
			r.MatchStatus = "fixed"
			r.FixedVersion = r.KBArticle
			label := installedSource[kb]
			if label == "" {
				for fkb, src := range installedSource {
					if isKBFixed(r.KBArticle, map[string]bool{fkb: true}) {
						label = src
						break
					}
				}
			}
			if label != "" {
				r.VerificationSource = label
			} else {
				r.VerificationSource = "local"
			}
		}
	}
	return results
}

func normalizeKBKey(kb string) string {
	return strings.ToUpper(strings.TrimSpace(kb))
}
