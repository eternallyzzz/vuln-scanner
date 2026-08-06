package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/store"
	"vuln-scanner/internal/ticket"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type RESTServer struct {
	store        *store.Store
	auth         *AgentAuth
	userAuth     *UserAuth
	apiKey       string
	cfg          *Config
	llmConfig    *LLMConfig
	register     *RegisterHandler
	worker       *Worker
	alerts       *alert.Service
	remoteCipher *remotescan.Cipher
	cloudCipher  *remotescan.Cipher
	tickets      *ticket.Service
}

type RegisterHandler struct {
	store  *store.Store
	auth   *AgentAuth
	srvURL string
}

// SetTicketService wires the optional ticket integration used for rule
// validation and the manual retry endpoint.
func (s *RESTServer) SetTicketService(t *ticket.Service) {
	s.tickets = t
}

func NewRESTServer(s *store.Store, auth *AgentAuth, cfg *Config, worker *Worker, alerts *alert.Service) *RESTServer {
	r := &RESTServer{
		store:     s,
		auth:      auth,
		userAuth:  NewUserAuth(cfg.JWTSecret),
		apiKey:    cfg.APIKey,
		cfg:       cfg,
		llmConfig: cfg.LLM,
		worker:    worker,
		alerts:    alerts,
		register: &RegisterHandler{
			store:  s,
			auth:   auth,
			srvURL: serverURL(cfg),
		},
	}
	if cfg.RemoteScan != nil && cfg.RemoteScan.Enabled {
		if raw := strings.TrimSpace(os.Getenv(cfg.RemoteScan.MasterKeyEnv)); raw != "" {
			if key, err := remotescan.ParseMasterKey(raw); err == nil {
				if cp, err := remotescan.NewCipher(key); err == nil {
					r.remoteCipher = cp
				}
			}
		}
	}
	if cfg.CloudScan != nil && cfg.CloudScan.Enabled {
		if raw := strings.TrimSpace(os.Getenv(cfg.CloudScan.MasterKeyEnv)); raw != "" {
			if key, err := remotescan.ParseMasterKey(raw); err == nil {
				if cp, err := remotescan.NewCipher(key); err == nil {
					r.cloudCipher = cp
				}
			}
		}
	}
	return r
}

// serverURL returns the externally reachable server base URL used by
// registration/install scripts. It must point at a host agents can reach, so
// production deployments should set server_url / SERVER_URL instead of
// relying on the localhost fallback.
func serverURL(cfg *Config) string {
	if cfg.ServerURL != "" {
		return strings.TrimSuffix(cfg.ServerURL, "/")
	}
	return "http://localhost" + cfg.HTTPAddr
}

func (s *RESTServer) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(s.userAuthMiddleware)
	r.Use(s.apiKeyMiddleware)
	r.Use(s.auditMiddleware)

	r.Get("/health", s.health)
	r.Get("/openapi.yaml", s.serveOpenAPI)
	r.Get("/demo", s.serveDemo)
	// Install scripts reference /dl/agent/<platform>; keep the single-segment
	// alias for backward compatibility.
	r.Get("/dl/agent/{platform}", s.downloadAgent)
	r.Get("/dl/{platform}", s.downloadAgent)
	r.Get("/r/{code}", s.downloadScript)
	r.Post("/api/v1/register", s.registerAgent)
	r.Post("/api/v1/auth/login", s.login)
	r.Post("/api/v1/auth/ldap/login", s.ldapLogin)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.enforceRBAC)
		r.Get("/auth/me", s.me)
		r.Post("/auth/change-password", s.changePassword)
		r.Get("/users", s.listUsers)
		r.Post("/users", s.createUser)
		r.Put("/users/{userId}", s.updateUser)
		r.Delete("/users/{userId}", s.deleteUser)
		r.Post("/users/{userId}/password", s.resetPassword)
		r.Get("/audit-logs", s.listAuditLogs)
		r.Get("/audit-logs/export.csv", s.exportAuditLogs)
		r.Get("/agents", s.listAgents)
		r.Post("/agents", s.addAgent)
		r.Get("/agents/{id}", s.getAgent)
		r.Delete("/agents/{id}", s.deleteAgent)
		r.Get("/agents/{id}/vulns", s.getAgentVulns)
		r.Get("/agents/{id}/vulns/{cveId}", s.getAgentVulnDetail)
		r.Get("/agents/{id}/report", s.getAgentReport)
		r.Get("/agents/{id}/system-info", s.getAgentSystemInfo)
		r.Get("/agents/{id}/update-facts", s.getAgentUpdateFacts)
		r.Get("/agents/{id}/update-status", s.getAgentUpdateStatus)
		r.Get("/agents/{id}/install-command", s.getInstallCommand)
		r.Get("/agents/{id}/recommendations", s.getRecommendations)
		r.Post("/agents/{id}/patch-tasks/generate", s.generatePatchTasks)
		r.Get("/agents/{id}/patch-tasks", s.listPatchTasks)
		r.Get("/patch-tasks", s.listPatchTasksGlobal)
		r.Get("/patch-tasks/{taskId}", s.getPatchTask)
		r.Post("/patch-tasks/{taskId}/approve", s.approvePatchTask)
		r.Post("/patch-tasks/{taskId}/reject", s.rejectPatchTask)
		r.Post("/patch-tasks/{taskId}/cancel", s.cancelPatchTask)
		r.Post("/patch-tasks/{taskId}/stop", s.stopPatchTask)
		r.Get("/patch-tasks/{taskId}/events", s.listPatchTaskEvents)
		r.Post("/patch-tasks/{taskId}/retry", s.retryPatchTask)
		r.Post("/patch-campaigns", s.generatePatchCampaign)
		r.Get("/patch-campaigns", s.listPatchCampaigns)
		r.Get("/patch-campaigns/{campaignId}", s.getPatchCampaign)
		r.Get("/patch-campaigns/{campaignId}/tasks", s.listPatchCampaignTasks)
		r.Post("/patch-campaigns/{campaignId}/approve", s.campaignApprove)
		r.Post("/patch-campaigns/{campaignId}/reject", s.campaignReject)
		r.Post("/patch-campaigns/{campaignId}/cancel", s.campaignCancel)
		r.Post("/patch-campaigns/{campaignId}/retry", s.campaignRetry)
		r.Get("/alert-rules", s.listAlertRules)
		r.Post("/alert-rules", s.createAlertRule)
		r.Get("/alert-rules/{ruleId}", s.getAlertRule)
		r.Put("/alert-rules/{ruleId}", s.updateAlertRule)
		r.Delete("/alert-rules/{ruleId}", s.deleteAlertRule)
		r.Post("/alert-rules/{ruleId}/test", s.testAlertRule)
		r.Get("/alerts", s.listAlerts)
		r.Post("/alerts/{alertId}/ack", s.ackAlert)
		r.Post("/alerts/{alertId}/resolve", s.resolveAlert)
		r.Post("/alerts/{alertId}/remediate", s.remediateAlert)
		r.Post("/alerts/{alertId}/ticket/retry", s.retryAlertTicket)

		r.Get("/dashboard", s.dashboard)
		r.Get("/demo-summary", s.demoSummary)
		r.Get("/risk/summary", s.getRiskSummary)
		r.Get("/risk/top", s.getRiskTop)
		r.Get("/risk/export.csv", s.getRiskExport)
		r.Get("/reports/trend", s.getRiskTrend)
		r.Get("/exceptions", s.listExceptions)
		r.Post("/exceptions", s.createException)
		r.Post("/exceptions/{exceptionId}/revoke", s.revokeException)
		r.Get("/sla-policies", s.listSLAPolicies)
		r.Put("/sla-policies/{policyId}", s.updateSLAPolicy)
		r.Get("/search", s.search)
		r.Get("/stats", s.stats)
		r.Get("/eol/summary", s.getEOLSummary)
		r.Get("/eol/agents", s.getEOLAgents)
		r.Get("/compliance/summary", s.getComplianceSummary)
		r.Get("/compliance/agents", s.listComplianceAgents)
		r.Get("/compliance/agents/{id}", s.getComplianceDetail)
		r.Get("/compliance/export.csv", s.exportComplianceCSV)
		r.Post("/analyze", s.triggerAnalysis)
		r.Get("/analyze/{analysisId}", s.getAnalysis)
		r.Post("/trigger-match", s.triggerMatch)
		r.Post("/admin/refresh-feeds", s.refreshFeeds)
		r.Post("/admin/refresh-intel", s.refreshIntel)
		r.Post("/admin/refresh-eol", s.refreshEOL)
		r.Post("/admin/report/send", s.sendReport)
		r.Post("/admin/check-sla", s.checkSLA)
		r.Post("/admin/reconcile-cmdb", s.reconcileAllCMDB)
		r.Post("/admin/reconcile-cmdb/{agentId}", s.reconcileAgentCMDB)
		r.Get("/scan-policies", s.listScanPolicies)
		r.Put("/scan-policies/{agentId}", s.upsertScanPolicy)
		r.Get("/network/hosts", s.listNetworkHosts)
		r.Get("/network/tasks", s.listNetworkScanTasks)
		r.Post("/network/scan", s.createNetworkScan)
		r.Get("/remote/credentials", s.listRemoteCredentials)
		r.Post("/remote/credentials", s.createRemoteCredential)
		r.Put("/remote/credentials/{credentialId}", s.updateRemoteCredential)
		r.Delete("/remote/credentials/{credentialId}", s.deleteRemoteCredential)
		r.Post("/remote/scan", s.createRemoteScan)
		r.Get("/remote/tasks", s.listRemoteScanTasks)
		r.Get("/remote/hosts", s.listRemoteHosts)
		r.Get("/cloud/accounts", s.listCloudAccounts)
		r.Post("/cloud/accounts", s.createCloudAccount)
		r.Put("/cloud/accounts/{accountId}", s.updateCloudAccount)
		r.Delete("/cloud/accounts/{accountId}", s.deleteCloudAccount)
		r.Post("/cloud/accounts/{accountId}/refresh", s.refreshCloudAccount)
		r.Get("/cloud/resources", s.listCloudResources)
		r.Get("/cloud/resources/export.csv", s.exportCloudResourcesCSV)
		r.Post("/agents/{id}/scan", s.triggerAgentScan)
		r.Post("/container/scan", s.triggerContainerScan)
		r.Get("/container/status", s.containerStatus)
		r.Get("/container/images", s.listContainerImages)
		r.Get("/assets/summary", s.assetSummary)
		r.Get("/assets", s.listAssets)
		r.Get("/assets/export", s.exportAssets)
		r.Post("/assets/import", s.importAssets)
		r.Get("/cmdb/reconcile-report", s.reconcileReport)
		r.Get("/assets/{assetId}", s.getAsset)
		r.Post("/assets/bulk-meta", s.bulkUpdateAssetMeta)
		r.Put("/assets/{assetId}", s.updateAsset)
		r.Get("/assets/{assetId}/changes", s.getAssetChanges)
		r.Get("/assets/{assetId}/relations", s.getAssetRelations)
	})

	return r
}

func (s *RESTServer) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFromContext(r.Context()) != nil {
			next.ServeHTTP(w, r)
			return
		}
		whiteList := map[string]bool{
			"/health":                 true,
			"/openapi.yaml":           true,
			"/demo":                   true,
			"/api/v1/register":        true,
			"/api/v1/auth/login":      true,
			"/api/v1/auth/ldap/login": true,
		}
		for prefix := range whiteList {
			if r.URL.Path == prefix {
				next.ServeHTTP(w, r)
				return
			}
		}
		if r.URL.Path == "/dl/linux-amd64" || r.URL.Path == "/dl/linux-arm64" ||
			r.URL.Path == "/dl/windows-amd64.exe" || r.URL.Path == "/dl/windows-arm64.exe" {
			next.ServeHTTP(w, r)
			return
		}
		if len(r.URL.Path) > 3 && r.URL.Path[:3] == "/r/" {
			next.ServeHTTP(w, r)
			return
		}
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/dl/" {
			next.ServeHTTP(w, r)
			return
		}

		if s.apiKey != "" {
			key := r.Header.Get("X-API-Key")
			if key != s.apiKey {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *RESTServer) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "version": "1.0.0"})
}

func (s *RESTServer) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, agents)
}

func (s *RESTServer) addAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname string `json:"hostname"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid body")
		return
	}

	agentID := generateID()

	parts := strings.SplitN(req.Platform, "-", 2)
	osType := "linux"
	arch := "amd64"
	if len(parts) == 2 {
		osType = parts[0]
		arch = parts[1]
	}

	agent := &store.Agent{
		ID:        agentID,
		Hostname:  req.Hostname,
		OSType:    osType,
		Arch:      arch,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.store.CreateAgent(r.Context(), agent); err != nil {
		writeError(w, 500, "create agent: "+err.Error())
		return
	}

	code := s.auth.GenerateRegCode()
	s.auth.StoreRegCode(code, agentID, req.Hostname, req.Platform)

	writeJSON(w, 201, map[string]string{
		"agent_id":    agentID,
		"code":        code,
		"install_cmd": registerCommand(s.register.srvURL, code, req.Platform),
	})
}

func registerCommand(srvURL, code, platform string) string {
	switch platform {
	case "linux-amd64", "linux-arm64":
		return "curl -fsSL " + srvURL + "/r/" + code + " | bash"
	case "windows-amd64", "windows-arm64":
		return "powershell -c \"irm " + srvURL + "/r/" + code + " | iex\""
	}
	return ""
}

func (s *RESTServer) getAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeError(w, 404, "agent not found")
		return
	}
	writeJSON(w, 200, agent)
}

func (s *RESTServer) deleteAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteAgent(r.Context(), id); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (s *RESTServer) getAgentVulns(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	severity := r.URL.Query().Get("severity")
	hasFix := r.URL.Query().Get("has_fix") == "true"

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size < 1 {
		size = 50
	}

	results, total, err := s.store.GetCVEResults(r.Context(), id, severity, hasFix, (page-1)*size, size)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	enrichAdvisoryURLs(results)

	agent, _ := s.store.GetAgent(r.Context(), id)

	writeJSON(w, 200, map[string]interface{}{
		"agent":           agent,
		"total":           total,
		"page":            page,
		"page_size":       size,
		"vulnerabilities": results,
	})
}

func (s *RESTServer) getAgentVulnDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cveID := chi.URLParam(r, "cveId")
	result, err := s.store.GetCVEResult(r.Context(), id, cveID)
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	enrichAdvisoryURLs([]store.CVEResult{*result})
	writeJSON(w, 200, result)
}

func (s *RESTServer) getAgentReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeError(w, 404, "agent not found")
		return
	}
	snapshot, _ := s.store.GetAssetSnapshot(r.Context(), id)
	results, _, _ := s.store.GetCVEResults(r.Context(), id, "", false, 0, 10000)
	enrichAdvisoryURLs(results)

	writeJSON(w, 200, map[string]interface{}{
		"agent":    agent,
		"snapshot": snapshot,
		"cves":     results,
	})
}

func (s *RESTServer) getInstallCommand(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeError(w, 404, "agent not found")
		return
	}
	code := s.auth.GenerateRegCode()
	s.auth.StoreRegCode(code, id, agent.Hostname, agent.OSType+"-"+agent.Arch)
	writeJSON(w, 200, map[string]string{
		"code":        code,
		"install_cmd": registerCommand(s.register.srvURL, code, agent.OSType+"-"+agent.Arch),
	})
}

func (s *RESTServer) dashboard(w http.ResponseWriter, r *http.Request) {
	agents, _ := s.store.ListAgents(r.Context())
	stats, _ := s.store.GetCVEStats(r.Context())

	onlineCount := 0
	for _, a := range agents {
		if a.Status == "online" {
			onlineCount++
		}
	}

	writeJSON(w, 200, map[string]interface{}{
		"total_agents":  len(agents),
		"online_agents": onlineCount,
		"cve_summary":   stats,
	})
}

func (s *RESTServer) search(w http.ResponseWriter, r *http.Request) {
	cveID := r.URL.Query().Get("cve")
	if cveID != "" {
		results, err := s.store.SearchByCVE(r.Context(), cveID)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		enrichAdvisoryURLs(results)
		writeJSON(w, 200, map[string]interface{}{
			"cve_id":          cveID,
			"affected_agents": results,
			"total":           len(results),
		})
		return
	}
	writeError(w, 400, "cve query required")
}

func (s *RESTServer) stats(w http.ResponseWriter, r *http.Request) {
	agents, _ := s.store.ListAgents(r.Context())
	cveStats, _ := s.store.GetCVEStats(r.Context())

	writeJSON(w, 200, map[string]interface{}{
		"total_agents": len(agents),
		"cve_summary":  cveStats,
	})
}

func (s *RESTServer) triggerAnalysis(w http.ResponseWriter, r *http.Request) {
	if s.llmConfig == nil {
		writeJSON(w, 501, map[string]string{"error": "LLM not configured"})
		return
	}
	writeJSON(w, 202, map[string]string{"status": "accepted", "analysis_id": ""})
}

func (s *RESTServer) getAnalysis(w http.ResponseWriter, r *http.Request) {
	analysisID := chi.URLParam(r, "analysisId")
	if analysisID == "" {
		writeError(w, 400, "analysis_id required")
		return
	}
	log, err := s.store.GetAnalysisLog(r.Context(), analysisID)
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, log)
}

func (s *RESTServer) downloadAgent(w http.ResponseWriter, r *http.Request) {
	platform := chi.URLParam(r, "platform")
	path := "./agents/" + platform
	slog.Info("agent download", "platform", platform)
	http.ServeFile(w, r, path)
}

func (s *RESTServer) downloadScript(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	srvURL := s.register.srvURL

	entry, ok := s.auth.ConsumeRegCode(code)
	if !ok {
		writeError(w, 404, "invalid or expired registration code")
		return
	}

	platform := entry.Platform
	switch platform {
	case "linux-amd64", "linux-arm64":
		w.Header().Set("Content-Type", "text/plain")
		script := "#!/bin/bash\n" +
			"curl -fsSL " + srvURL + "/dl/agent/" + platform + " -o /tmp/vuln-agent && " +
			"chmod +x /tmp/vuln-agent && " +
			"/tmp/vuln-agent install " + code + "\n"
		w.Write([]byte(script))
	case "windows-amd64", "windows-arm64":
		w.Header().Set("Content-Type", "text/plain")
		script := "$temp = Join-Path $env:TEMP \"vuln-agent.exe\"\n" +
			"Invoke-WebRequest \"" + srvURL + "/dl/agent/" + platform + "\" -OutFile $temp\n" +
			"& $temp install " + code + "\n"
		w.Write([]byte(script))
	default:
		writeError(w, 400, "unsupported platform")
	}
}

func (s *RESTServer) registerAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		Hostname string `json:"hostname"`
		OSType   string `json:"os_type"`
		Version  string `json:"os_version"`
		Arch     string `json:"arch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid body")
		return
	}

	entry, ok := s.auth.ConsumeRegCode(req.Code)
	if !ok {
		writeError(w, 404, "invalid or expired registration code")
		return
	}

	s.store.UpdateAgentStatus(r.Context(), entry.AgentID, "pending")

	writeJSON(w, 200, map[string]interface{}{
		"agent_id":  entry.AgentID,
		"grpc_addr": grpcAddrForRequest(r, s.cfg.GRPCAddr),
	})
}

// grpcAddrForRequest derives the gRPC address an agent should dial from the
// host it used for the HTTP registration request, keeping the configured gRPC
// port. This allows agents on remote hosts to register successfully instead of
// being pointed at localhost.
func grpcAddrForRequest(r *http.Request, grpcCfg string) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "localhost"
	}
	_, port, err := net.SplitHostPort(grpcCfg)
	if err != nil || port == "" {
		port = "9090"
	}
	return net.JoinHostPort(host, port)
}

func generateID() string {
	u := fmt.Sprintf("%d", time.Now().UnixNano())
	return "agent-" + u[len(u)-12:]
}

func (s *RESTServer) triggerMatch(w http.ResponseWriter, r *http.Request) {
	go s.worker.RunMatchCycle(context.Background())
	writeJSON(w, 200, map[string]string{"status": "match_cycle_triggered"})
}

func (s *RESTServer) refreshFeeds(w http.ResponseWriter, r *http.Request) {
	go s.worker.RefreshFeeds(context.Background())
	writeJSON(w, 200, map[string]string{"status": "feed_refresh_triggered"})
}

func (s *RESTServer) getRecommendations(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	recs, err := s.store.GetAgentRecommendations(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil || agent == nil {
		writeError(w, 404, "agent not found")
		return
	}
	kbMeta := loadKBMetadata(r.Context(), s.store, recs)
	for i := range recs {
		rec := &recs[i]
		if rec.FixType == "kb" {
			rec.ReferenceURL = advisoryURLFor(rec.ExampleCVE, rec.ReferenceURL)
			enrichKBLinks(rec.KBs, kbMeta)
			if len(rec.KBs) > 0 {
				if m, ok := kbMeta[rec.KBs[0].Kb]; ok {
					rec.PatchURL = bestPatchURL(m)
					rec.PatchSHA256 = m.DownloadSHA256
				}
				if rec.PatchURL == "" {
					rec.PatchURL = rec.KBs[0].PatchURL
				}
			}
		}
		cmd, err := patch.BuildCommandForAgent(s.cfg.Patch, rec.FixType,
			rec.FixedVersion, rec.AssetName, rec.PatchURL, rec.PatchSHA256,
			agent.OSType, agent.OSVersion)
		if err == nil && cmd.Deployable {
			rec.Deployable = true
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id":        id,
		"recommendations": recs,
	})
}
