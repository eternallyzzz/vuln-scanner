package cve

import (
	"strconv"
	"strings"
)

// compareRPMVersions compares full RPM EVR strings of the form
// `[epoch:]version[-release]` (arch suffixes are stripped when present).
// Comparison order is epoch (numeric), then version, then release, using
// rpmvercmp semantics for the latter two.
func compareRPMVersions(a, b string) int {
	ae, av, ar := splitRPMEVR(a)
	be, bv, br := splitRPMEVR(b)
	if c := compareRPMEpoch(ae, be); c != 0 {
		return c
	}
	if c := rpmvercmp(av, bv); c != 0 {
		return c
	}
	return rpmvercmp(ar, br)
}

func splitRPMEVR(evr string) (epoch, version, release string) {
	evr = stripRPMArch(evr)
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		epoch = evr[:i]
		evr = evr[i+1:]
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		release = evr[i+1:]
		version = evr[:i]
	} else {
		version = evr
	}
	return epoch, version, release
}

func stripRPMArch(evr string) string {
	i := strings.LastIndexByte(evr, '.')
	if i < 0 {
		return evr
	}
	switch strings.ToLower(evr[i+1:]) {
	case "x86_64", "i386", "i486", "i586", "i686", "noarch", "aarch64",
		"armv7hl", "armv6hl", "ppc64", "ppc64le", "s390", "s390x", "src":
		return evr[:i]
	}
	return evr
}

func compareRPMEpoch(a, b string) int {
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	an, aerr := strconv.ParseInt(a, 10, 64)
	bn, berr := strconv.ParseInt(b, 10, 64)
	if aerr == nil && berr == nil {
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

// rpmvercmp implements the RPM version comparison algorithm. It ignores
// non-alphanumeric separators, treats "~" as lower than everything (pre-release)
// and "^" as higher than everything (post-release), compares digit runs
// numerically and alpha runs lexicographically.
func rpmvercmp(a, b string) int {
	for {
		a = skipRPMSeparators(a)
		b = skipRPMSeparators(b)

		aTilde := strings.HasPrefix(a, "~")
		bTilde := strings.HasPrefix(b, "~")
		if aTilde != bTilde {
			if aTilde {
				return -1
			}
			return 1
		}
		if aTilde {
			a, b = a[1:], b[1:]
			continue
		}

		aCaret := strings.HasPrefix(a, "^")
		bCaret := strings.HasPrefix(b, "^")
		if aCaret != bCaret {
			if aCaret {
				return 1
			}
			return -1
		}
		if aCaret {
			a, b = a[1:], b[1:]
			continue
		}

		switch {
		case a == "" && b == "":
			return 0
		case a == "":
			return -1
		case b == "":
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
		if c := strings.Compare(aSeg, bSeg); c != 0 {
			return c
		}
		a, b = aRest, bRest
	}
}

func skipRPMSeparators(s string) string {
	for len(s) > 0 && !isRPMAlnum(s[0]) && s[0] != '~' && s[0] != '^' {
		s = s[1:]
	}
	return s
}

func takeRPMDigits(s string) (seg, rest string) {
	i := 0
	for i < len(s) && isASCIIDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func takeRPMAlpha(s string) (seg, rest string) {
	i := 0
	for i < len(s) && isASCIIAlpha(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func compareRPMNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) > len(b) {
			return 1
		}
		return -1
	}
	return strings.Compare(a, b)
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isASCIIAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isRPMAlnum(c byte) bool {
	return isASCIIDigit(c) || isASCIIAlpha(c)
}

// isRPMEcosystem reports whether an OSV/feed ecosystem uses RPM EVR version
// strings (rpm-based Linux distributions).
func isRPMEcosystem(ecosystem string) bool {
	lower := strings.ToLower(ecosystem)
	switch {
	case strings.HasPrefix(lower, "red hat"),
		strings.HasPrefix(lower, "alma"),
		strings.HasPrefix(lower, "rocky"),
		strings.HasPrefix(lower, "fedora"),
		strings.HasPrefix(lower, "centos"),
		strings.HasPrefix(lower, "suse"),
		strings.HasPrefix(lower, "opensuse"):
		return true
	}
	return lower == "rpm"
}
