package cve

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// compareVersions is the generic version comparator used by OSV/non-distro
// ecosystems and asset-version bookkeeping. It prefers real semver ordering
// (pre-release/build metadata aware) and falls back to numeric segment
// comparison for versions semver cannot parse.
func compareVersions(a, b string) int {
	ca, aOK := canonicalSemver(a)
	cb, bOK := canonicalSemver(b)
	if aOK && bOK {
		return semver.Compare(ca, cb)
	}
	return compareNumericVersionParts(a, b)
}

func canonicalSemver(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	c := semver.Canonical("v" + v)
	if c == "" {
		return "", false
	}
	return c, true
}

func compareNumericVersionParts(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	a = cleanVersion(a)
	b = cleanVersion(b)

	aSegs := strings.Split(a, ".")
	bSegs := strings.Split(b, ".")

	for i := 0; i < len(aSegs) || i < len(bSegs); i++ {
		var aNum, bNum int64

		if i < len(aSegs) {
			n, err := strconv.ParseInt(aSegs[i], 10, 64)
			if err != nil {
				return strings.Compare(a, b)
			}
			aNum = n
		}
		if i < len(bSegs) {
			n, err := strconv.ParseInt(bSegs[i], 10, 64)
			if err != nil {
				return strings.Compare(a, b)
			}
			bNum = n
		}

		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

// compareDpkgVersions compares Debian version strings of the form
// `[epoch:]upstream[-revision]`. Epochs compare numerically first, then
// upstream, then revision. A tilde sorts before everything, including the end
// of a string, matching dpkg pre-release semantics.
func compareDpkgVersions(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	ae, au, ar := splitDpkgVersion(a)
	be, bu, br := splitDpkgVersion(b)
	if c := compareDpkgEpoch(ae, be); c != 0 {
		return c
	}
	if c := compareDpkgOrdered(au, bu); c != 0 {
		return c
	}
	return compareDpkgOrdered(ar, br)
}

func splitDpkgVersion(v string) (epoch, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = v[:i]
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		revision = v[i+1:]
		upstream = v[:i]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

func compareDpkgEpoch(a, b string) int {
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	an, aErr := strconv.ParseInt(a, 10, 64)
	bn, bErr := strconv.ParseInt(b, 10, 64)
	if aErr == nil && bErr == nil {
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

func compareDpkgOrdered(a, b string) int {
	for {
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

		aNon, aRest := takeDpkgNonDigits(a)
		bNon, bRest := takeDpkgNonDigits(b)
		if c := compareDpkgNonDigits(aNon, bNon); c != 0 {
			return c
		}
		a, b = aRest, bRest

		aDig, aRest := takeDpkgDigits(a)
		bDig, bRest := takeDpkgDigits(b)
		if aDig == "" && bDig == "" {
			return 0
		}
		if c := compareDpkgNumeric(aDig, bDig); c != 0 {
			return c
		}
		a, b = aRest, bRest
	}
}

func takeDpkgNonDigits(s string) (string, string) {
	i := 0
	for i < len(s) && !isASCIIDigit(s[i]) && s[i] != '~' {
		i++
	}
	return s[:i], s[i:]
}

func takeDpkgDigits(s string) (string, string) {
	i := 0
	for i < len(s) && isASCIIDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func compareDpkgNonDigits(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		if i >= len(a) {
			return -1
		}
		if i >= len(b) {
			return 1
		}
		if a[i] == b[i] {
			continue
		}
		ra, rb := dpkgCharClass(a[i]), dpkgCharClass(b[i])
		if ra != rb {
			if ra < rb {
				return -1
			}
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
		return 1
	}
	return 0
}

func dpkgCharClass(c byte) int {
	if isASCIIAlpha(c) {
		return 0
	}
	return 1
}

func compareDpkgNumeric(a, b string) int {
	return compareRPMNumeric(a, b)
}
