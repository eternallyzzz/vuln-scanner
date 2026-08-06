package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/store"
)

// listAuditLogs is the admin-only unified audit query endpoint.
func (s *RESTServer) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var since, until *time.Time
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, 400, "since must be RFC3339")
			return
		}
		since = &t
	}
	if raw := strings.TrimSpace(q.Get("until")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, 400, "until must be RFC3339")
			return
		}
		until = &t
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	filter := store.AuditLogFilter{
		Actor:    strings.TrimSpace(q.Get("actor")),
		Method:   strings.ToUpper(strings.TrimSpace(q.Get("method"))),
		Path:     q.Get("path"),
		Since:    since,
		Until:    until,
		TenantID: tid,
		Limit:    limit,
		Offset:   offset,
	}

	entries, err := s.store.ListAuditLogs(r.Context(), filter)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	total, err := s.store.CountAuditLogs(r.Context(), filter)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"total":   total,
		"entries": entries,
	})
}

// exportAuditLogs streams the latest 5000 audit entries as CSV.
func (s *RESTServer) exportAuditLogs(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	data, err := s.store.AuditExportCSV(r.Context(), tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-logs.csv"`)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
