package cve

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// compareVersions is the generic version comparator used by OSV/non-distro
// ecosystems and asset-version bookkeeping. It follows the probe chain used
// by Wazuh's vulnerability scanner (CalVer -> PEP440 -> MajorMinor -> SemVer)
// and keeps the numeric segment comparison as a final fallback so versions
// that match none of the structured formats still order deterministically.
func compareVersions(a, b string) int {
	if c, ok := compareCalVer(a, b); ok {
		return c
	}
	if c, ok := comparePEP440(a, b); ok {
		return c
	}
	if c, ok := compareMajorMinor(a, b); ok {
		return c
	}
	ca, aOK := canonicalSemver(a)
	cb, bOK := canonicalSemver(b)
	if aOK && bOK {
		return semver.Compare(ca, cb)
	}
	return compareNumericVersionParts(a, b)
}

var calVerRe = regexp.MustCompile(`^(\d{2}|\d{4})(?:\.(\d{1,2}))?(?:\.(\d{1,2}))?(?:\.(\d+))?$`)

// parseCalVer parses calendar versions of the form
// `(YY|YYYY)[.MM][.DD][.micro]`, matching Wazuh's CalVer semantics: a year
// with either two or four digits, then optional 1-2 digit month/day fields
// and an optional numeric micro segment. Absent fields compare as zero.
func parseCalVer(v string) (year, month, day, micro int, ok bool) {
	m := calVerRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, 0, 0, false
	}
	year, _ = strconv.Atoi(m[1])
	if m[2] != "" {
		month, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		day, _ = strconv.Atoi(m[3])
	}
	if m[4] != "" {
		micro, _ = strconv.Atoi(m[4])
	}
	return year, month, day, micro, true
}

// compareCalVer compares two calendar versions numerically field by field.
// It reports ok=false when either side is not a CalVer, letting the caller
// fall through to the next comparator in the chain.
func compareCalVer(a, b string) (int, bool) {
	ay, am, ad, au, aok := parseCalVer(a)
	by, bm, bd, bu, bok := parseCalVer(b)
	if !aok || !bok {
		return 0, false
	}
	for _, pair := range [][2]int{{ay, by}, {am, bm}, {ad, bd}, {au, bu}} {
		switch {
		case pair[0] < pair[1]:
			return -1, true
		case pair[0] > pair[1]:
			return 1, true
		}
	}
	return 0, true
}

var majorMinorRe = regexp.MustCompile(`^(\d+)[.\-](\d+)$`)

func parseMajorMinor(v string) (major, minor int, ok bool) {
	m := majorMinorRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}

// compareMajorMinor compares `major(.|-)minor` versions numerically. It is a
// narrow format kept for parity with Wazuh's MajorMinor object; PEP440
// already covers most of these strings, so it mostly acts as a safety net.
func compareMajorMinor(a, b string) (int, bool) {
	amaj, amin, aok := parseMajorMinor(a)
	bmaj, bmin, bok := parseMajorMinor(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case amaj < bmaj:
		return -1, true
	case amaj > bmaj:
		return 1, true
	case amin < bmin:
		return -1, true
	case amin > bmin:
		return 1, true
	}
	return 0, true
}

type pep440Version struct {
	epoch   int
	release []int
	pre     int // -1 when absent
	preNum  int
	post    int // -1 when absent
	dev     int // -1 when absent
}

// parsePEP440 parses PEP 440 version strings with the same shape Wazuh's
// version object accepts: `[v][epoch!]release[pre][post][dev]`, where pre is
// one of a/alpha, b/beta, c/rc/pre/preview and post one of post/rev/r or an
// implicit `-N` suffix. Local version labels (+local) are intentionally not
// supported, mirroring the upstream regex.
func parsePEP440(v string) (pep440Version, bool) {
	out := pep440Version{pre: -1, post: -1, dev: -1}
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return out, false
	}
	if i := strings.IndexByte(s, '!'); i >= 0 {
		if i == 0 {
			return out, false
		}
		epoch, err := strconv.Atoi(s[:i])
		if err != nil {
			return out, false
		}
		out.epoch = epoch
		s = s[i+1:]
	}

	release, rest, ok := parsePEP440Release(s)
	if !ok {
		return out, false
	}
	out.release = release
	s = rest

	if letter, num, rest, ok := parsePEP440Pre(s); ok {
		out.pre, out.preNum = letter, num
		s = rest
	}
	if num, rest, ok := parsePEP440Post(s); ok {
		out.post = num
		s = rest
	}
	if num, rest, ok := parsePEP440Dev(s); ok {
		out.dev = num
		s = rest
	}
	if s != "" {
		return out, false
	}
	return out, true
}

func parsePEP440Release(s string) ([]int, string, bool) {
	dig, rest, ok := takePEP440Digits(s)
	if !ok {
		return nil, s, false
	}
	release := []int{atoiPEP440(dig)}
	for strings.HasPrefix(rest, ".") {
		dig, after, ok := takePEP440Digits(rest[1:])
		if !ok {
			// A dot followed by a non-digit starts a pre/post/dev segment
			// (e.g. "1.0.post1"), not another release component.
			break
		}
		release = append(release, atoiPEP440(dig))
		rest = after
	}
	return release, rest, true
}

func takePEP440Digits(s string) (string, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", s, false
	}
	return s[:i], s[i:], true
}

func atoiPEP440(digits string) int {
	n, _ := strconv.Atoi(digits)
	return n
}

func skipPEP440Sep(s string) string {
	if s != "" && (s[0] == '-' || s[0] == '_' || s[0] == '.') {
		return s[1:]
	}
	return s
}

func parsePEP440Pre(s string) (letter, num int, rest string, ok bool) {
	rest = skipPEP440Sep(s)
	token, after := matchPEP440PreToken(rest)
	if token < 0 {
		return 0, 0, s, false
	}
	rest = skipPEP440Sep(after)
	num = 0
	if dig, r, ok := takePEP440Digits(rest); ok {
		num = atoiPEP440(dig)
		rest = r
	}
	return token, num, rest, true
}

func matchPEP440PreToken(s string) (int, string) {
	lower := strings.ToLower(s)
	for _, t := range []struct {
		token  string
		letter int
	}{
		{"alpha", 0},
		{"beta", 1},
		{"preview", 2},
		{"pre", 2},
		{"rc", 2},
		{"c", 2},
		{"a", 0},
		{"b", 1},
	} {
		if strings.HasPrefix(lower, t.token) {
			return t.letter, s[len(t.token):]
		}
	}
	return -1, s
}

func parsePEP440Post(s string) (num int, rest string, ok bool) {
	// PEP 440 shorthand: release directly followed by -N is an implicit post.
	if strings.HasPrefix(s, "-") {
		if dig, r, ok := takePEP440Digits(s[1:]); ok {
			return atoiPEP440(dig), r, true
		}
	}
	rest = skipPEP440Sep(s)
	lower := strings.ToLower(rest)
	token := ""
	switch {
	case strings.HasPrefix(lower, "post"):
		token = "post"
	case strings.HasPrefix(lower, "rev"):
		token = "rev"
	case strings.HasPrefix(lower, "r"):
		token = "r"
	}
	if token == "" {
		return 0, s, false
	}
	rest = skipPEP440Sep(rest[len(token):])
	num = 0
	if dig, r, ok := takePEP440Digits(rest); ok {
		num = atoiPEP440(dig)
		rest = r
	}
	return num, rest, true
}

func parsePEP440Dev(s string) (num int, rest string, ok bool) {
	rest = skipPEP440Sep(s)
	if !strings.HasPrefix(strings.ToLower(rest), "dev") {
		return 0, s, false
	}
	rest = skipPEP440Sep(rest[3:])
	num = 0
	if dig, r, ok := takePEP440Digits(rest); ok {
		num = atoiPEP440(dig)
		rest = r
	}
	return num, rest, true
}

// comparePEP440 implements the PEP 440 ordering: epoch, release (zero padded),
// then pre/dev/post with the special rule that a bare dev release sorts before
// any pre-release, while a final release sorts after pre-releases and before
// post-releases.
func comparePEP440(a, b string) (int, bool) {
	va, aok := parsePEP440(a)
	vb, bok := parsePEP440(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case va.epoch < vb.epoch:
		return -1, true
	case va.epoch > vb.epoch:
		return 1, true
	}
	if c := compareIntSlices(va.release, vb.release); c != 0 {
		return c, true
	}
	if c := comparePEP440Pre(va, vb); c != 0 {
		return c, true
	}
	if c := comparePEP440Post(va, vb); c != 0 {
		return c, true
	}
	if c := comparePEP440Dev(va, vb); c != 0 {
		return c, true
	}
	return 0, true
}

func compareIntSlices(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// pep440PreRank encodes how a version's pre-release state participates in
// ordering: a bare dev release ranks below every pre-release (-1), an actual
// pre-release ranks as 0 (compared by letter/number afterwards), and a final
// or post release ranks above every pre-release (1).
func pep440PreRank(v pep440Version) int {
	if v.pre >= 0 {
		return 0
	}
	if v.post < 0 && v.dev >= 0 {
		return -1
	}
	return 1
}

func comparePEP440Pre(a, b pep440Version) int {
	ar, br := pep440PreRank(a), pep440PreRank(b)
	switch {
	case ar < br:
		return -1
	case ar > br:
		return 1
	}
	if ar != 0 {
		return 0
	}
	switch {
	case a.pre < b.pre:
		return -1
	case a.pre > b.pre:
		return 1
	case a.preNum < b.preNum:
		return -1
	case a.preNum > b.preNum:
		return 1
	}
	return 0
}

func comparePEP440Post(a, b pep440Version) int {
	switch {
	case a.post < 0 && b.post < 0:
		return 0
	case a.post < 0:
		return -1
	case b.post < 0:
		return 1
	case a.post < b.post:
		return -1
	case a.post > b.post:
		return 1
	}
	return 0
}

func comparePEP440Dev(a, b pep440Version) int {
	switch {
	case a.dev >= 0 && b.dev >= 0:
		switch {
		case a.dev < b.dev:
			return -1
		case a.dev > b.dev:
			return 1
		}
		return 0
	case a.dev >= 0:
		return -1
	case b.dev >= 0:
		return 1
	}
	return 0
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
