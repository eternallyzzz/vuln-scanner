package server

import "net/http"

func (s *RESTServer) getEOLSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.store.EOLSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, sum)
}

func (s *RESTServer) getEOLAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListAgentsEOL(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"total": len(rows), "agents": rows})
}

func (s *RESTServer) refreshEOL(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil {
		writeError(w, 500, "worker not available")
		return
	}
	updated, err := s.worker.RefreshEOL(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"updated": updated, "status": "ok"})
}
