package server

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func (s *RESTServer) getComplianceSummary(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	sum, err := s.store.ComplianceSummary(r.Context(), tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, sum)
}

func (s *RESTServer) listComplianceAgents(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	rows, err := s.store.ListComplianceAgents(r.Context(), tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"total": len(rows), "agents": rows})
}

func (s *RESTServer) getComplianceDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.requireAgent(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	rep, err := s.store.GetComplianceReport(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "no compliance report for agent")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rep)
}

func (s *RESTServer) exportComplianceCSV(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	data, err := s.store.ComplianceExportCSV(r.Context(), tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="compliance-export.csv"`)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
