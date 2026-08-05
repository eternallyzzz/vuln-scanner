package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/ldap"
	"vuln-scanner/internal/store"
)

// ldapLogin authenticates against the configured LDAP directory and reuses
// the local JWT/RBAC/audit chain. The directory decides who may log in via
// role group membership; an existing local user always keeps its local role
// and status, so admins can pin or disable accounts locally.
func (s *RESTServer) ldapLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg == nil || s.cfg.LDAP == nil || !s.cfg.LDAP.Enabled {
		writeError(w, 400, "ldap login not enabled")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	username := strings.TrimSpace(in.Username)

	identity, err := ldap.Authenticate(s.cfg.LDAP, username, in.Password)
	if err != nil {
		if errors.Is(err, ldap.ErrInvalidCredentials) {
			slog.Info("ldap login rejected", "username", username)
			writeError(w, 401, "invalid credentials")
			return
		}
		slog.Error("ldap authentication failed", "username", username, "error", err)
		writeError(w, 500, "ldap authentication unavailable")
		return
	}

	role := ldap.MapRole(identity.Groups, s.cfg.LDAP.RoleGroups)
	if role == "" {
		slog.Info("ldap login rejected: no mapped role", "username", username)
		writeError(w, 403, "no mapped role")
		return
	}

	u, err := s.store.GetUserByUsername(r.Context(), username)
	if errors.Is(err, pgx.ErrNoRows) {
		if !s.cfg.LDAP.AutoProvision {
			slog.Info("ldap login rejected: auto_provision disabled", "username", username)
			writeError(w, 401, "invalid credentials")
			return
		}
		displayName := identity.DisplayName
		if displayName == "" {
			displayName = username
		}
		u, err = s.store.CreateUser(r.Context(), username, "", displayName, role)
		if errors.Is(err, store.ErrUserExists) {
			// Concurrent provisioning: keep the existing local account.
			u, err = s.store.GetUserByUsername(r.Context(), username)
		}
	}
	if err != nil {
		slog.Error("ldap login user lookup failed", "username", username, "error", err)
		writeError(w, 500, "user lookup failed")
		return
	}
	if u.Status != "active" {
		slog.Info("ldap login rejected: local user not active", "username", username)
		writeError(w, 401, "invalid credentials")
		return
	}

	token, expiresAt, err := s.userAuth.IssueToken(u)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	setAuditActor(r.Context(), u.Username)
	_ = s.store.TouchUserLogin(r.Context(), u.ID)
	writeJSON(w, 200, map[string]interface{}{
		"token":      token,
		"expires_at": expiresAt,
		"user":       publicUser(u),
	})
}
