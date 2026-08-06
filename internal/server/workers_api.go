package server

import "net/http"

// listWorkers reports the current loop leases and pending job queue depth.
// It is admin-only and exists to verify multi-instance horizontal scaling.
func (s *RESTServer) listWorkers(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeError(w, 500, "store unavailable")
		return
	}
	leases, err := s.store.ListWorkerLeases(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	counts, err := s.store.PendingJobCounts(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if counts == nil {
		counts = map[string]int64{}
	}
	writeJSON(w, 200, map[string]interface{}{
		"leases": leases,
		"queues": counts,
	})
}
