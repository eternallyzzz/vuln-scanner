package server

import (
	"net/http"
)

func (s *RESTServer) triggerContainerScan(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ContainerScan == nil || !s.cfg.ContainerScan.Enabled {
		writeError(w, 400, "container scanning is disabled")
		return
	}
	if s.worker == nil {
		writeError(w, 500, "worker unavailable")
		return
	}
	s.worker.TriggerContainerScan()
	writeJSON(w, 202, map[string]string{"status": "scan_triggered"})
}

func (s *RESTServer) containerStatus(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil {
		writeError(w, 500, "worker unavailable")
		return
	}
	writeJSON(w, 200, s.worker.ContainerStatus())
}

func (s *RESTServer) listContainerImages(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ContainerScan == nil || !s.cfg.ContainerScan.Enabled {
		writeError(w, 400, "container scanning is disabled")
		return
	}
	images, err := s.store.GetContainerImages(r.Context(), s.cfg.ContainerScan.AgentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"images": images, "total": len(images)})
}
