package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,64}$`)

func validRole(role string) bool {
	switch role {
	case "admin", "operator", "viewer":
		return true
	}
	return false
}

func validPassword(password string) bool {
	return len(password) >= 8
}

func publicUser(u *store.User) map[string]interface{} {
	return map[string]interface{}{
		"id":           u.ID,
		"username":     u.Username,
		"display_name": u.DisplayName,
		"role":         u.Role,
		"status":       u.Status,
	}
}

func (s *RESTServer) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(in.Username))
	if err != nil || u.Status != "active" || !checkPassword(u.PasswordHash, in.Password) {
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

func (s *RESTServer) me(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	if u == nil {
		writeError(w, 401, "not authenticated")
		return
	}
	full, err := s.store.GetUserByID(r.Context(), u.ID)
	if err != nil {
		writeError(w, 401, "user no longer exists")
		return
	}
	writeJSON(w, 200, publicUser(full))
}

func (s *RESTServer) changePassword(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	if u == nil {
		writeError(w, 401, "not authenticated")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	full, err := s.store.GetUserByID(r.Context(), u.ID)
	if err != nil {
		writeError(w, 401, "user no longer exists")
		return
	}
	if !checkPassword(full.PasswordHash, in.CurrentPassword) {
		writeError(w, 400, "current password is incorrect")
		return
	}
	if !validPassword(in.NewPassword) {
		writeError(w, 400, "new password must be at least 8 characters")
		return
	}
	hash, err := hashPassword(in.NewPassword)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), u.ID, hash); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"status": "ok"})
}

func (s *RESTServer) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	out := make([]map[string]interface{}, 0, len(users))
	for i := range users {
		out = append(out, publicUser(&users[i]))
	}
	writeJSON(w, 200, map[string]interface{}{"users": out})
}

func (s *RESTServer) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Role = strings.TrimSpace(in.Role)
	if !usernamePattern.MatchString(in.Username) {
		writeError(w, 400, "username must be 3-64 chars of [A-Za-z0-9_.-]")
		return
	}
	if !validPassword(in.Password) {
		writeError(w, 400, "password must be at least 8 characters")
		return
	}
	if !validRole(in.Role) {
		writeError(w, 400, "role must be admin, operator or viewer")
		return
	}
	hash, err := hashPassword(in.Password)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	u, err := s.store.CreateUser(r.Context(), in.Username, hash, in.DisplayName, in.Role)
	if err == store.ErrUserExists {
		writeError(w, 409, "username already exists")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, publicUser(u))
}

func (s *RESTServer) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid user id")
		return
	}
	cur := userFromContext(r.Context())
	if cur != nil && cur.ID == id {
		writeError(w, 400, "cannot modify your own user via this endpoint")
		return
	}
	var in struct {
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Status      string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if in.Role != "" && !validRole(in.Role) {
		writeError(w, 400, "role must be admin, operator or viewer")
		return
	}
	if in.Status != "" && in.Status != "active" && in.Status != "disabled" {
		writeError(w, 400, "status must be active or disabled")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, 404, "user not found")
		return
	}
	role := target.Role
	if in.Role != "" {
		role = in.Role
	}
	status := target.Status
	if in.Status != "" {
		status = in.Status
	}
	// Never strand the system without an active admin.
	if target.Role == "admin" && target.Status == "active" &&
		(role != "admin" || status != "active") {
		admins, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		if admins <= 1 {
			writeError(w, 400, "cannot demote or disable the last active admin")
			return
		}
	}
	displayName := in.DisplayName
	if displayName == "" {
		displayName = target.DisplayName
	}
	if err := s.store.UpdateUser(r.Context(), id, displayName, role, status); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"user_id": id, "status": "updated"})
}

func (s *RESTServer) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid user id")
		return
	}
	cur := userFromContext(r.Context())
	if cur != nil && cur.ID == id {
		writeError(w, 400, "cannot delete your own user")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, 404, "user not found")
		return
	}
	if target.Role == "admin" && target.Status == "active" {
		admins, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		if admins <= 1 {
			writeError(w, 400, "cannot delete the last active admin")
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"user_id": id, "status": "deleted"})
}

func (s *RESTServer) resetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid user id")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if !validPassword(in.Password) {
		writeError(w, 400, "password must be at least 8 characters")
		return
	}
	if _, err := s.store.GetUserByID(r.Context(), id); err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, 404, "user not found")
		} else {
			writeError(w, 500, err.Error())
		}
		return
	}
	hash, err := hashPassword(in.Password)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"user_id": id, "status": "password updated"})
}
