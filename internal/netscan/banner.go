package netscan

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ServiceName maps well-known TCP ports to a canonical service name.
func ServiceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 25:
		return "smtp"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	}
	return fmt.Sprintf("tcp-%d", port)
}

var (
	sshRe     = regexp.MustCompile(`(?i)SSH-\d+\.\d+-([A-Za-z0-9.+-]+)(?:_([0-9][A-Za-z0-9_.+-]*))?`)
	httpRe    = regexp.MustCompile(`(?i)^Server:\s*([A-Za-z0-9_.+-]+)(?:/([0-9][A-Za-z0-9_.-]*))?`)
	ftpRe     = regexp.MustCompile(`(?i)(vsFTPd|ProFTPD)\s+([0-9][A-Za-z0-9_.-]*)`)
	eximRe    = regexp.MustCompile(`(?i)Exim\s+([0-9][A-Za-z0-9_.-]*)`)
	postfixRe = regexp.MustCompile(`(?i)Postfix`)
)

// ParseBanner extracts a canonical product and version from a service
// banner. It is best-effort; unknown banners return empty values and callers
// fall back to the port-derived service name.
func ParseBanner(port int, banner string) (product, version string) {
	switch port {
	case 22:
		if m := sshRe.FindStringSubmatch(banner); len(m) >= 3 {
			return normalizeProduct(m[1]), m[2]
		}
	case 80, 8080:
		for _, line := range strings.Split(banner, "\r\n") {
			if m := httpRe.FindStringSubmatch(line); len(m) >= 3 {
				return normalizeProduct(m[1]), m[2]
			}
		}
	case 21:
		if m := ftpRe.FindStringSubmatch(banner); len(m) >= 3 {
			return normalizeProduct(m[1]), m[2]
		}
	case 25:
		if m := eximRe.FindStringSubmatch(banner); len(m) >= 2 {
			return "exim", m[1]
		}
		if postfixRe.MatchString(banner) {
			return "postfix", ""
		}
	}
	return "", ""
}

func normalizeProduct(s string) string {
	p := strings.ToLower(s)
	switch p {
	case "openssh":
		return "openssh"
	case "dropbear":
		return "dropbear"
	case "nginx":
		return "nginx"
	case "apache":
		return "apache"
	case "vsftpd", "proftpd":
		return p
	}
	return p
}

// grabBanner connects to the service and reads up to one line/response.
// HTTP ports get a minimal HEAD request so the Server header is available.
func grabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)
	if port == 80 || port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(buf[:n])
}

// GuessOS heuristically maps an open-port set to an OS family.
func GuessOS(ports []int) string {
	for _, p := range ports {
		if p == 445 || p == 139 {
			return "windows"
		}
	}
	for _, p := range ports {
		if p == 22 {
			return "linux"
		}
	}
	return "unknown"
}
