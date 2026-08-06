package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func (s *RESTServer) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	keys, err := s.store.ListAPIKeys(r.Context(), tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
}

func (s *RESTServer) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		TenantID *int64 `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	var tenantID *int64
	if in.TenantID != nil && *in.TenantID > 0 {
		exists, err := s.store.TenantExists(r.Context(), *in.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !exists {
			writeError(w, http.StatusBadRequest, "invalid or unknown tenant_id")
			return
		}
		tenantID = in.TenantID
	} else {
		id, restrict, err := s.scope(r)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if restrict {
			tenantID = &id
		}
	}

	key, plain, err := s.store.CreateAPIKey(r.Context(), in.Name, tenantID, actorFromRequest(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"key":     plain,
		"api_key": key,
		"warning": "store this key now; the plaintext will not be shown again",
	})
}

func (s *RESTServer) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "keyId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid key id")
		return
	}
	key, err := s.store.GetAPIKey(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tid, restrict, err := s.scope(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	if restrict {
		if key.TenantID == nil || *key.TenantID != tid {
			writeError(w, http.StatusForbidden, "forbidden: key belongs to another tenant")
			return
		}
	}
	if err := s.store.RevokeAPIKey(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "key not found or already revoked")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"key_id": id, "revoked": true})
}
