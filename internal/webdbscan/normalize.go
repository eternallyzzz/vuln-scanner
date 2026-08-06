package webdbscan

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidDBTypes lists the database protocols supported in v1.
func ValidDBTypes() []string {
	return []string{"postgresql", "mysql", "redis"}
}

// IsValidDBType reports whether dbType is supported.
func IsValidDBType(dbType string) bool {
	switch strings.ToLower(strings.TrimSpace(dbType)) {
	case "postgresql", "mysql", "redis":
		return true
	}
	return false
}

// DefaultDBPort returns the default TCP port for a database type.
func DefaultDBPort(dbType string) int {
	switch strings.ToLower(strings.TrimSpace(dbType)) {
	case "postgresql":
		return 5432
	case "mysql":
		return 3306
	case "redis":
		return 6379
	}
	return 0
}

// NormalizeWebTarget accepts a URL or a host[:port][/path] shorthand and
// returns a canonical http(s) URL. IPv6 hosts must be bracketed.
func NormalizeWebTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("invalid web target")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid web target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("web target scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("web target host is required")
	}
	if u.User != nil {
		return "", errors.New("web target userinfo is not supported, use a credential instead")
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", errors.New("invalid web target port")
		}
	}
	return u.String(), nil
}

// NormalizeDBTarget accepts host[:port] and returns host:port using the
// type-specific default port. IPv6 hosts must be bracketed.
func NormalizeDBTarget(raw, dbType string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n/\\\"") {
		return "", errors.New("invalid database target")
	}
	host := raw
	port := DefaultDBPort(dbType)
	if strings.Contains(raw, ":") {
		h, p, err := net.SplitHostPort(raw)
		if err != nil {
			return "", fmt.Errorf("invalid database target: %w", err)
		}
		host = h
		parsed, err := strconv.Atoi(p)
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", errors.New("invalid database target port")
		}
		port = parsed
	}
	if host == "" {
		return "", errors.New("invalid database host")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("invalid database host")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
