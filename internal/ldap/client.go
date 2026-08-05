package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// ErrInvalidCredentials collapses credential failures (empty password,
// unknown/non-unique user, wrong password) into one error so callers can
// return a uniform 401 without revealing account existence.
var ErrInvalidCredentials = errors.New("invalid LDAP credentials")

// Identity is the authenticated directory entry plus its group memberships.
type Identity struct {
	Username    string
	DisplayName string
	UserDN      string
	Groups      []string
}

// Dial connects to the configured LDAP server with a bounded timeout.
// ldap:// and ldaps:// URLs are supported; tls_skip_verify only applies to
// ldaps:// connections.
func Dial(cfg *Config) (*goldap.Conn, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("ldap url not configured")
	}
	opts := []goldap.DialOpt{
		goldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout()}),
	}
	scheme := strings.ToLower(strings.SplitN(cfg.URL, "://", 2)[0])
	if scheme == "ldaps" {
		opts = append(opts, goldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	return goldap.DialURL(cfg.URL, opts...)
}

// Authenticate resolves the user DN with the service account, verifies the
// user password with a direct bind, then reads group membership using the
// service account again. Credential failures are collapsed into
// ErrInvalidCredentials; directory/network failures are returned as-is for
// server-side logging.
func Authenticate(cfg *Config, username, password string) (*Identity, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, errors.New("ldap not enabled")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("ldap config invalid: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	svc, err := Dial(cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer svc.Close()
	if err := svc.Bind(cfg.BindDN, cfg.Password()); err != nil {
		return nil, fmt.Errorf("ldap service bind: %w", err)
	}

	userFilter := replacePlaceholders(cfg.UserFilter, username, "")
	userRes, err := svc.Search(goldap.NewSearchRequest(
		cfg.UserBaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1, 0, false,
		userFilter,
		[]string{"displayName", "cn", "uid", "sAMAccountName"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap user search: %w", err)
	}
	if len(userRes.Entries) != 1 || userRes.Entries[0].DN == "" {
		return nil, ErrInvalidCredentials
	}
	entry := userRes.Entries[0]

	userConn, err := Dial(cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer userConn.Close()
	if err := userConn.Bind(entry.DN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	identity := &Identity{
		Username:    username,
		DisplayName: firstAttribute(entry, "displayName", "cn"),
		UserDN:      entry.DN,
	}
	if identity.DisplayName == "" {
		identity.DisplayName = username
	}

	if cfg.GroupFilter != "" {
		groupFilter := replacePlaceholders(cfg.GroupFilter, username, entry.DN)
		groupRes, err := svc.Search(goldap.NewSearchRequest(
			cfg.GroupBaseDN,
			goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases,
			0, 0, false,
			groupFilter,
			[]string{"cn", "name", "sAMAccountName"},
			nil,
		))
		if err != nil {
			return nil, fmt.Errorf("ldap group search: %w", err)
		}
		for _, g := range groupRes.Entries {
			if g.DN != "" {
				identity.Groups = append(identity.Groups, g.DN)
			}
			for _, name := range []string{"cn", "name", "sAMAccountName"} {
				if v := g.GetAttributeValue(name); v != "" {
					identity.Groups = append(identity.Groups, v)
				}
			}
		}
	}
	return identity, nil
}

func firstAttribute(entry *goldap.Entry, names ...string) string {
	for _, name := range names {
		if v := entry.GetAttributeValue(name); v != "" {
			return v
		}
	}
	return ""
}
