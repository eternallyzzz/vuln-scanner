package webdbscan

import (
	"html"
	"regexp"
	"strings"
)

// WebFingerprintInput is the raw signal set used by FingerprintWeb.
type WebFingerprintInput struct {
	Server        string
	XPoweredBy    string
	XGenerator    string
	Title         string
	MetaGenerator string
	Body          string
}

var (
	serverRe        = regexp.MustCompile(`(?i)^([A-Za-z][A-Za-z0-9_.+-]*)(?:/([0-9][A-Za-z0-9_.-]*))?`)
	phpRe           = regexp.MustCompile(`(?i)^php/([0-9][A-Za-z0-9_.-]*)`)
	wordpressRe     = regexp.MustCompile(`(?i)wordpress(?:[ /]([0-9][A-Za-z0-9_.-]*))?`)
	joomlaRe        = regexp.MustCompile(`(?i)joomla!?(?:[ /]([0-9][A-Za-z0-9_.-]*))?`)
	drupalRe        = regexp.MustCompile(`(?i)drupal(?:[ /]([0-9][A-Za-z0-9_.-]*))?`)
	ghostRe         = regexp.MustCompile(`(?i)ghost(?:[ /]([0-9][A-Za-z0-9_.-]*))?`)
	hugoRe          = regexp.MustCompile(`(?i)hugo(?:[ /]([0-9][A-Za-z0-9_.-]*))?`)
	titleRe         = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaGeneratorRe = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']?generator["']?[^>]+content\s*=\s*["']([^"']+)`)
)

func extractTitle(body string) string {
	if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
		return html.UnescapeString(stripHTML(m[1]))
	}
	return ""
}

func extractMetaGenerator(body string) string {
	if m := metaGeneratorRe.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func stripHTML(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// FingerprintWeb maps raw HTTP signals to canonical products. Unknown
// signals produce no products; the caller still records the raw headers and
// title on the target row.
func FingerprintWeb(in WebFingerprintInput) []Product {
	var out []Product
	add := func(name, version, evidence string) {
		if hasProduct(out, name) {
			return
		}
		out = append(out, Product{Name: name, Version: version, Evidence: evidence})
	}

	if s := strings.TrimSpace(in.Server); s != "" {
		if product, version := parseServerHeader(s); product != "" {
			add(product, version, "Server: "+s)
		}
	}
	if s := strings.TrimSpace(in.XPoweredBy); s != "" {
		if m := phpRe.FindStringSubmatch(s); len(m) > 1 {
			add("php", m[1], "X-Powered-By: "+s)
		}
	}
	for _, s := range []string{strings.TrimSpace(in.MetaGenerator), strings.TrimSpace(in.XGenerator)} {
		if s == "" {
			continue
		}
		switch {
		case wordpressRe.MatchString(s):
			add("wordpress", versionOf(wordpressRe, s), "Generator: "+s)
		case joomlaRe.MatchString(s):
			add("joomla", versionOf(joomlaRe, s), "Generator: "+s)
		case drupalRe.MatchString(s):
			add("drupal", versionOf(drupalRe, s), "Generator: "+s)
		case ghostRe.MatchString(s):
			add("ghost", versionOf(ghostRe, s), "Generator: "+s)
		case hugoRe.MatchString(s):
			add("hugo", versionOf(hugoRe, s), "Generator: "+s)
		}
	}
	lowerBody := strings.ToLower(in.Body)
	if !hasProduct(out, "wordpress") &&
		(strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-includes")) {
		out = append(out, Product{Name: "wordpress", Evidence: "body: wp-content/wp-includes"})
	}
	return out
}

func versionOf(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

func hasProduct(products []Product, name string) bool {
	for _, p := range products {
		if strings.EqualFold(p.Name, name) {
			return true
		}
	}
	return false
}

func parseServerHeader(s string) (product, version string) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", ""
	}
	m := serverRe.FindStringSubmatch(fields[0])
	if len(m) < 2 {
		return "", ""
	}
	name := strings.ToLower(m[1])
	ver := ""
	if len(m) > 2 {
		ver = m[2]
	}
	switch name {
	case "nginx", "openresty":
		return "nginx", ver
	case "apache":
		return "apache", ver
	case "microsoft-iis", "iis":
		return "iis", ver
	case "apache-coyote", "coyote", "tomcat":
		return "tomcat", ver
	case "lighttpd":
		return "lighttpd", ver
	case "caddy":
		return "caddy", ver
	}
	return "", ""
}
