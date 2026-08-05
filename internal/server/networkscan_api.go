package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"vuln-scanner/internal/netscan"
)

func (s *RESTServer) listNetworkHosts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	hosts, total, err := s.store.ListNetworkHosts(r.Context(), limit, offset)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"total": total,
		"hosts": hosts,
	})
}

func (s *RESTServer) listNetworkScanTasks(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	tasks, total, err := s.store.ListNetworkScanTasks(r.Context(), status, limit, offset)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"total": total,
		"tasks": tasks,
	})
}

func (s *RESTServer) createNetworkScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string  `json:"target"`
		Ports  []int32 `json:"ports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	target := strings.TrimSpace(in.Target)
	if !validNetworkTarget(target) {
		writeError(w, 400, "target must be an IPv4 address or CIDR")
		return
	}
	ports := in.Ports
	if len(ports) == 0 {
		for _, p := range netscan.DefaultPorts() {
			ports = append(ports, int32(p))
		}
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			writeError(w, 400, "ports must be in 1-65535")
			return
		}
	}
	task, err := s.store.CreateNetworkScanTask(r.Context(), target, ports, actorFromRequest(r))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]interface{}{"task": task})
}

func validNetworkTarget(raw string) bool {
	if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
		return true
	}
	ip, _, err := net.ParseCIDR(raw)
	return err == nil && ip.To4() != nil
}
