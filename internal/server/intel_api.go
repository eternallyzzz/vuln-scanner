package server

import (
	"net/http"
	"strconv"
	"strings"
)

// listCustomIntel returns the built-in proprietary intel rules. Rules are
// maintained as migration seeds (code-only); this endpoint is read-only.
func (s *RESTServer) listCustomIntel(w http.ResponseWriter, r *http.Request) {
	enabled := strings.TrimSpace(r.URL.Query().Get("enabled"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	rules, total, err := s.store.ListCustomIntel(r.Context(), enabled, q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "rules": rules})
}

// listCVEIntelAnnotations returns the built-in CVE intel annotations.
// Annotations are maintained as migration seeds (code-only); this endpoint is
// read-only and reflects whatever the current database migration seeded.
func (s *RESTServer) listCVEIntelAnnotations(w http.ResponseWriter, r *http.Request) {
	enabled := strings.TrimSpace(r.URL.Query().Get("enabled"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	annotations, total, err := s.store.ListCVEIntelAnnotations(r.Context(), enabled, q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "annotations": annotations})
}
