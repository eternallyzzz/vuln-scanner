package server

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/store"
)

//go:embed demo.html
var demoFiles embed.FS

var demoPage = template.Must(template.New("demo").Parse(mustLoadDemoPage()))

func mustLoadDemoPage() string {
	data, err := demoFiles.ReadFile("demo.html")
	if err != nil {
		panic(err)
	}
	return string(data)
}

// serveDemo renders the test showcase page. The API key is injected server
// side so the page works from a plain browser without headers.
func (s *RESTServer) serveDemo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := demoPage.Execute(w, struct{ APIKey string }{APIKey: s.apiKey}); err != nil {
		http.Error(w, "render demo page: "+err.Error(), http.StatusInternalServerError)
	}
}

// demoSummary merges the store aggregates with worker-owned container state.
func (s *RESTServer) demoSummary(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.DemoSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	container := map[string]interface{}{"enabled": false}
	if s.worker != nil {
		container = s.worker.ContainerStatus()
	}
	writeJSON(w, 200, map[string]interface{}{
		"agents":       ds.Agents,
		"assets":       ds.Assets,
		"cves":         ds.CVEs,
		"alerts":       ds.Alerts,
		"patch":        ds.Patch,
		"cmdb":         ds.CMDB,
		"container":    container,
		"generated_at": ds.GeneratedAt,
	})
}

// getAgentSystemInfo returns the latest host telemetry for one agent.
func (s *RESTServer) getAgentSystemInfo(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.requireAgent(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	info, err := s.store.GetHostSystemInfo(r.Context(), id)
	if store.IsHostSystemInfoNotFound(err) {
		writeError(w, 404, "no host system info reported yet")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, info)
}

// getAgentUpdateFacts returns the latest WUA/WSUS update facts for one agent.
func (s *RESTServer) getAgentUpdateFacts(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.requireAgent(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	facts, err := s.store.GetAgentUpdateFacts(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if facts == nil {
		facts = []collector.UpdateFact{}
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id":     id,
		"update_facts": facts,
	})
}

// getAgentUpdateStatus returns the latest WUA/WSUS reachability record.
func (s *RESTServer) getAgentUpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.requireAgent(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	status, err := s.store.GetAgentUpdateStatus(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if status == nil {
		status = &collector.UpdateSourceStatus{SourceReachable: false, Error: "not reported"}
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id":      id,
		"update_status": status,
	})
}
