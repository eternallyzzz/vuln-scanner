package cve

import (
	"strings"
)

// apkVersionCompare compares Alpine package versions of the form
// `[epoch:]version[-rN]` following apk-tools ordering:
//   - epochs compare numerically;
//   - digit segments compare numerically and are newer than letter segments;
//   - letter segments sort as alpha < beta < pre < rc < plain < p;
//   - non-alphanumeric characters act as separators;
//   - a shorter version is older.
func apkVersionCompare(a, b string) int {
	ae, av, aEpoch := splitAPKEpoch(a)
	be, bv, bEpoch := splitAPKEpoch(b)
	if aEpoch || bEpoch {
		if c := compareRPMEpoch(ae, be); c != 0 {
			return c
		}
	}
	return apkvercmp(av, bv)
}

func splitAPKEpoch(v string) (epoch, rest string, hasEpoch bool) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		return v[:i], v[i+1:], true
	}
	return "", v, false
}

func apkvercmp(a, b string) int {
	for {
		a = skipAPKSeparators(a)
		b = skipAPKSeparators(b)

		switch {
		case a == "" && b == "":
			return 0
		case a == "":
			// b is longer: pre-release suffixes sort before a plain version.
			if isASCIIAlpha(b[0]) && apkPreReleaseRank(alphaRun(b)) != 0 {
				return 1
			}
			return -1
		case b == "":
			if isASCIIAlpha(a[0]) && apkPreReleaseRank(alphaRun(a)) != 0 {
				return -1
			}
			return 1
		}

		aDigit := isASCIIDigit(a[0])
		bDigit := isASCIIDigit(b[0])
		if aDigit != bDigit {
			if aDigit {
				return 1
			}
			return -1
		}

		if aDigit {
			aSeg, aRest := takeRPMDigits(a)
			bSeg, bRest := takeRPMDigits(b)
			if c := compareRPMNumeric(aSeg, bSeg); c != 0 {
				return c
			}
			a, b = aRest, bRest
			continue
		}

		aSeg, aRest := takeRPMAlpha(a)
		bSeg, bRest := takeRPMAlpha(b)
		if c := compareAPKAlpha(aSeg, bSeg); c != 0 {
			return c
		}
		a, b = aRest, bRest
	}
}

func skipAPKSeparators(s string) string {
	for len(s) > 0 && !isRPMAlnum(s[0]) {
		s = s[1:]
	}
	return s
}

func alphaRun(s string) string {
	seg, _ := takeRPMAlpha(s)
	return seg
}

// apkPreReleaseRank returns a nonzero rank for pre-release suffix words that
// sort before a plain version ("alpha" < "beta" < "pre" < "rc").
func apkPreReleaseRank(word string) int {
	switch strings.ToLower(word) {
	case "alpha":
		return 1
	case "beta":
		return 2
	case "pre":
		return 3
	case "rc":
		return 4
	default:
		return 0
	}
}

func compareAPKAlpha(a, b string) int {
	ra := apkAlphaRank(a)
	rb := apkAlphaRank(b)
	if ra != rb {
		if ra < rb {
			return -1
		}
		return 1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// apkAlphaRank orders alpha runs: pre-release suffixes, then plain text, then
// the post-release "p" marker.
func apkAlphaRank(word string) int {
	lower := strings.ToLower(word)
	switch lower {
	case "alpha":
		return 1
	case "beta":
		return 2
	case "pre":
		return 3
	case "rc":
		return 4
	case "p":
		return 6
	default:
		return 5
	}
}

// isAPKEcosystem reports whether an OSV/feed ecosystem uses Alpine apk version
// strings ("Alpine" or "Alpine:v3.x").
func isAPKEcosystem(ecosystem string) bool {
	return strings.HasPrefix(strings.ToLower(ecosystem), "alpine")
}

// alpineEcosystemVersion extracts the distro version from OSV Alpine ecosystem
// names such as "Alpine:v3.17" -> "3.17"; empty when absent.
func alpineEcosystemVersion(ecosystem string) string {
	s := strings.ToLower(ecosystem)
	if !strings.HasPrefix(s, "alpine:v") {
		return ""
	}
	v := s[len("alpine:v"):]
	if v == "" {
		return ""
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r == '.') {
			return ""
		}
	}
	return v
}

// majorMinorFromVersion returns the first two dot-separated tokens of an OS
// version ("3.23.3" -> "3.23", "9.8" -> "9.8").
func majorMinorFromVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}
