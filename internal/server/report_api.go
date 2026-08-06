package server

import "net/http"

// sendReport manually triggers the panorama report pipeline and delivers it
// by email. It is admin-only and will itself appear in the unified audit log.
func (s *RESTServer) sendReport(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil {
		writeError(w, 500, "worker not available")
		return
	}
	sentAt, err := s.worker.SendReportNow(r.Context(), nil)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"status":       "sent",
		"generated_at": sentAt,
	})
}
