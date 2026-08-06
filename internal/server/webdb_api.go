package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"vuln-scanner/internal/store"
	"vuln-scanner/internal/webdbscan"

	"github.com/go-chi/chi/v5"
)

const maxWebDBTargets = 100

func (s *RESTServer) listWebDBCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListWebDBCredentials(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for i := range creds {
		out = append(out, webDBCredentialView(&creds[i]))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": out})
}

func (s *RESTServer) createWebDBCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if in.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}
	if s.webdbCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "web/db scan is disabled or the master key is not configured")
		return
	}
	cipher, err := s.webdbCipher.Encrypt([]byte(in.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cred, err := s.store.CreateWebDBCredential(r.Context(), name, strings.TrimSpace(in.Username), cipher, actorFromRequest(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"credential": webDBCredentialView(cred)})
}

func (s *RESTServer) updateWebDBCredential(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "credentialId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	var in struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if s.webdbCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "web/db scan is disabled or the master key is not configured")
		return
	}
	existing, err := s.store.GetWebDBCredential(r.Context(), id)
	if errors.Is(err, store.ErrWebDBCredentialNotFound) {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = existing.Name
	}
	username := strings.TrimSpace(in.Username)
	if username == "" {
		username = existing.Username
	}
	cipher := existing.PasswordCiphertext
	if in.Password != "" {
		enc, err := s.webdbCipher.Encrypt([]byte(in.Password))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cipher = enc
	}
	if err := s.store.UpdateWebDBCredential(r.Context(), id, name, username, cipher); err != nil {
		if errors.Is(err, store.ErrWebDBCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := s.store.GetWebDBCredential(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credential": webDBCredentialView(updated)})
}

func (s *RESTServer) deleteWebDBCredential(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "credentialId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	if _, err := s.store.GetWebDBCredential(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrWebDBCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.RevokeWebDBCredential(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *RESTServer) createWebDBScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Web []string `json:"web"`
		DB  []struct {
			Target       string `json:"target"`
			DBType       string `json:"db_type"`
			CredentialID int64  `json:"credential_id"`
		} `json:"db"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if len(in.Web) == 0 && len(in.DB) == 0 {
		writeError(w, http.StatusBadRequest, "at least one web or db target is required")
		return
	}
	if len(in.Web) > maxWebDBTargets {
		writeError(w, http.StatusBadRequest, "at most 100 web targets per scan")
		return
	}
	if len(in.DB) > maxWebDBTargets {
		writeError(w, http.StatusBadRequest, "at most 100 db targets per scan")
		return
	}
	if s.webdbCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "web/db scan is disabled or the master key is not configured")
		return
	}

	inputs := make([]store.WebDBTaskInput, 0, len(in.Web)+len(in.DB))
	for _, raw := range in.Web {
		target, err := webdbscan.NormalizeWebTarget(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid web target "+strconv.Quote(raw)+": "+err.Error())
			return
		}
		inputs = append(inputs, store.WebDBTaskInput{Kind: "web", Target: target})
	}
	for _, db := range in.DB {
		dbType := strings.ToLower(strings.TrimSpace(db.DBType))
		if !webdbscan.IsValidDBType(dbType) {
			writeError(w, http.StatusBadRequest, "db_type must be one of postgresql, mysql, redis")
			return
		}
		if db.CredentialID < 0 {
			writeError(w, http.StatusBadRequest, "credential_id must be positive or omitted")
			return
		}
		target, err := webdbscan.NormalizeDBTarget(db.Target, dbType)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid db target "+strconv.Quote(db.Target)+": "+err.Error())
			return
		}
		inputs = append(inputs, store.WebDBTaskInput{
			Kind:         "db",
			Target:       target,
			DBType:       dbType,
			CredentialID: db.CredentialID,
		})
	}

	tasks, err := s.store.CreateWebDBScanTasks(r.Context(), inputs, actorFromRequest(r))
	if errors.Is(err, store.ErrWebDBCredentialNotFound) {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if errors.Is(err, store.ErrWebDBCredentialRevoked) {
		writeError(w, http.StatusBadRequest, "credential is revoked")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.worker != nil {
		s.worker.TriggerWebDBScan()
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"count": len(tasks),
		"tasks": tasks,
	})
}

func (s *RESTServer) listWebDBScanTasks(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	tasks, total, err := s.store.ListWebDBScanTasks(r.Context(), status, kind, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "tasks": tasks})
}

func (s *RESTServer) listWebDBTargets(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	targets, total, err := s.store.ListWebDBTargets(r.Context(), kind, q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "targets": targets})
}

func webDBCredentialView(c *store.WebDBCredential) map[string]interface{} {
	return map[string]interface{}{
		"id":         c.ID,
		"name":       c.Name,
		"username":   c.Username,
		"created_by": c.CreatedBy,
		"created_at": c.CreatedAt,
		"updated_at": c.UpdatedAt,
		"revoked_at": c.RevokedAt,
	}
}
