package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/cloudscan"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/report"
	"vuln-scanner/internal/siem"
	"vuln-scanner/internal/store"
	"vuln-scanner/internal/ticket"
	"vuln-scanner/internal/webdbscan"
)

type Worker struct {
	store    *store.Store
	loader   *cve.Loader
	match    *cve.Matcher
	alerts   *alert.Service
	patchCfg *patch.Config
	feedCfg  *cve.Config

	mode     string
	workerID string
	hostname string

	done             chan struct{}
	wakeCh           chan struct{}
	containerCfg     *container.Config
	containerScanner *container.Scanner
	containerMu      sync.Mutex
	containerState   containerScanState
	reportCfg        *report.Config
	reportSMTP       *alert.SMTPConfig
	reportMu         sync.Mutex
	reportRunning    bool
	auditRetention   time.Duration
	remoteCfg        *remotescan.Config
	remoteKey        []byte
	tickets          *ticket.Service
	siem             *siem.Service
	cloudCfg         *cloudscan.Config
	cloudKey         []byte
	webdbCfg         *webdbscan.Config
	webdbKey         []byte
}

func NewWorker(s *store.Store, loader *cve.Loader, matcher *cve.Matcher, alerts *alert.Service, patchCfg *patch.Config, feedCfg ...*cve.Config) *Worker {
	cfg := cve.DefaultConfig()
	if len(feedCfg) > 0 && feedCfg[0] != nil {
		cfg = feedCfg[0].Normalized()
	}
	hostname, _ := os.Hostname()
	w := &Worker{
		store:    s,
		loader:   loader,
		match:    matcher,
		alerts:   alerts,
		patchCfg: patchCfg,
		feedCfg:  cfg,
		mode:     "all",
		hostname: hostname,
		workerID: fmt.Sprintf("%s-%d-%s", sanitizeHostname(hostname), os.Getpid(), randSuffix(4)),
		done:     make(chan struct{}),
		wakeCh:   make(chan struct{}, 1),
	}
	if alerts != nil {
		alerts.SetOnNewAlert(w.handleNewAlert)
	}
	return w
}

func sanitizeHostname(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func randSuffix(n int) string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	seed := uint64(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		b.WriteByte(chars[seed>>33%uint64(len(chars))])
	}
	return b.String()
}

// SetMode sets the instance role: all (default), api (HTTP/gRPC only) or
// worker (background loops only). It must be called before Start.
func (w *Worker) SetMode(mode string) error {
	switch mode {
	case "all", "api", "worker":
		w.mode = mode
		return nil
	default:
		return fmt.Errorf("invalid mode %q: must be all, api or worker", mode)
	}
}

func (w *Worker) Start(ctx context.Context) {
	if w.mode == "api" {
		slog.Info("api mode: background loops disabled", "worker", w.workerID)
		return
	}
	slog.Info("worker starting", "mode", w.mode, "worker", w.workerID)
	if w.alerts != nil {
		w.alerts.SetWorkerID(w.workerID)
	}
	go w.jobNotifyListener(ctx)
	go w.jobMaintenanceLoop(ctx)

	// Single-runner loops (lease elected).
	go w.runLeaseLoop(ctx, "feed", w.feedLoop)
	go w.runLeaseLoop(ctx, "match", w.matchCycleLoop)
	go w.runLeaseLoop(ctx, "scan_policy", w.scanPolicyLoop)
	go w.runLeaseLoop(ctx, "sla", w.slaLoop)
	go w.runLeaseLoop(ctx, "eol", w.eolLoop)
	if w.reportCfg != nil && w.reportCfg.Enabled {
		go w.runLeaseLoop(ctx, "report", w.reportLoop)
	}
	if w.containerCfg != nil && w.containerCfg.Enabled {
		go w.runLeaseLoop(ctx, "container", w.containerScanLoop)
	}
	go w.runLeaseLoop(ctx, "archive", w.archiveLoop)
	go w.runLeaseLoop(ctx, "reap_patch", w.reapPatchLoop)

	// Parallel loops (DB-claimed, safe on every worker).
	go w.matchJobLoop(ctx)
	go w.remediationJobLoop(ctx)
	go w.remoteScanLoop(ctx)
	if w.tickets != nil {
		go w.ticketLoop(ctx)
	}
	if w.siem != nil {
		go w.siemLoop(ctx)
	}
	if w.cloudCfg != nil {
		go w.cloudLoop(ctx)
	}
	if w.webdbCfg != nil {
		go w.webdbLoop(ctx)
	}
	if w.alerts != nil && w.alerts.Enabled() {
		go w.alerts.RunDeliveryLoop(ctx)
	}
}

// ConfigureCloudScanning enables the background cloud asset discovery loop.
func (w *Worker) ConfigureCloudScanning(cfg *cloudscan.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	raw := strings.TrimSpace(os.Getenv(cfg.MasterKeyEnv))
	key, err := remotescan.ParseMasterKey(raw)
	if err != nil {
		slog.Error("cloud scan disabled: invalid master key", "error", err)
		return
	}
	w.cloudCfg = cfg.Normalized()
	w.cloudKey = key
	slog.Info("cloud scan enabled",
		"concurrency", w.cloudCfg.Concurrency,
		"default_refresh_interval_minutes", w.cloudCfg.DefaultRefreshIntervalMinutes)
}

// TriggerCloudRefresh enqueues one coalesced cloud refresh job.
func (w *Worker) TriggerCloudRefresh(accountID int64) {
	if w.cloudCfg == nil {
		return
	}
	w.enqueue("cloud_refresh", fmt.Sprintf("%d", accountID),
		map[string]interface{}{"account_id": accountID})
}

// ConfigureWebDBScanning enables the background web/database scan worker.
// The AES-256 master key is read from the environment variable named by
// cfg.MasterKeyEnv; a missing or invalid key disables the loop with a log.
func (w *Worker) ConfigureWebDBScanning(cfg *webdbscan.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	raw := strings.TrimSpace(os.Getenv(cfg.MasterKeyEnv))
	key, err := remotescan.ParseMasterKey(raw)
	if err != nil {
		slog.Error("webdb scan disabled: invalid master key", "error", err)
		return
	}
	w.webdbCfg = cfg.Normalized()
	w.webdbKey = key
	slog.Info("webdb scan enabled",
		"concurrency", w.webdbCfg.Concurrency,
		"timeout_seconds", w.webdbCfg.TimeoutSeconds)
}

// TriggerWebDBScan wakes the webdb worker loop via the shared job channel.
func (w *Worker) TriggerWebDBScan() {
	if w.webdbCfg == nil {
		return
	}
	w.enqueue("webdb_wakeup", "", nil)
}

// ConfigureSIEM enables the background SIEM/SOAR outbox worker.
func (w *Worker) ConfigureSIEM(cfg *siem.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	svc, err := siem.NewService(cfg)
	if err != nil {
		slog.Error("siem disabled: invalid config", "error", err)
		return
	}
	w.siem = svc
	w.store.SetSiemEnabled(true)
	slog.Info("siem enabled",
		"interval_seconds", svc.Config().DeliveryIntervalSeconds,
		"batch_size", svc.Config().BatchSize)
}

// TriggerSIEM wakes the SIEM worker loop via the shared job channel.
func (w *Worker) TriggerSIEM() {
	if w.siem == nil {
		return
	}
	w.enqueue("siem_wakeup", "", nil)
}

// ConfigureRemoteScanning enables the server-side credential scan worker.
// The AES-256 master key is read from the environment variable named by
// cfg.MasterKeyEnv; a missing or invalid key disables the loop with a log.
func (w *Worker) ConfigureRemoteScanning(cfg *remotescan.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	raw := strings.TrimSpace(os.Getenv(cfg.MasterKeyEnv))
	key, err := remotescan.ParseMasterKey(raw)
	if err != nil {
		slog.Error("remote scan disabled: invalid master key", "error", err)
		return
	}
	w.remoteCfg = cfg.Normalized()
	w.remoteKey = key
	slog.Info("remote scan enabled",
		"concurrency", w.remoteCfg.Concurrency, "timeout_seconds", w.remoteCfg.TimeoutSeconds)
}

// ConfigureTicketing enables the background ticket create/sync worker.
func (w *Worker) ConfigureTicketing(cfg *ticket.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	svc, err := ticket.NewService(cfg)
	if err != nil {
		slog.Error("ticketing disabled: invalid config", "error", err)
		return
	}
	w.tickets = svc
	slog.Info("ticketing enabled",
		"provider", svc.Config().Provider, "base_url", svc.Config().BaseURL)
}

// TicketService returns the configured ticket service, or nil.
func (w *Worker) TicketService() *ticket.Service {
	if w == nil {
		return nil
	}
	return w.tickets
}

// TriggerTicket wakes the ticket worker loop via the shared job channel.
func (w *Worker) TriggerTicket() {
	if w.tickets == nil {
		return
	}
	w.enqueue("ticket_wakeup", "", nil)
}

// TriggerRemoteScan wakes the remote scan worker via the shared job channel.
func (w *Worker) TriggerRemoteScan() {
	if w.remoteCfg == nil {
		return
	}
	w.enqueue("remote_scan_wakeup", "", nil)
}

// remoteScanLoop polls pending remote scan tasks every 10 seconds and runs
// them with the configured concurrency.
func (w *Worker) remoteScanLoop(ctx context.Context) {
	cfg := w.remoteCfg
	if cfg == nil || !cfg.Enabled {
		return
	}
	sem := make(chan struct{}, cfg.Concurrency)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	slog.Info("remote scan loop started", "concurrency", cfg.Concurrency)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		tasks, err := w.store.ClaimRemoteScanTasks(ctx, cfg.Concurrency)
		if err != nil {
			slog.Error("claim remote scan tasks failed", "error", err)
			continue
		}
		for _, t := range tasks {
			sem <- struct{}{}
			go func(t store.RemoteScanTask) {
				defer func() { <-sem }()
				w.runRemoteScanTask(context.Background(), t, cfg)
			}(t)
		}
	}
}

func (w *Worker) runRemoteScanTask(ctx context.Context, task store.RemoteScanTask, cfg *remotescan.Config) {
	start := time.Now()
	cred, err := w.store.GetRemoteCredential(ctx, task.CredentialID)
	if err != nil {
		w.finishRemoteTask(ctx, task, err, nil)
		return
	}
	if cred.RevokedAt != nil {
		w.finishRemoteTask(ctx, task, errors.New("credential revoked"), nil)
		return
	}
	cp, err := remotescan.NewCipher(w.remoteKey)
	if err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("init credential cipher: %w", err), nil)
		return
	}
	pwd, err := cp.Decrypt(cred.PasswordCiphertext)
	if err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("decrypt password: %w", err), nil)
		return
	}
	key, err := cp.Decrypt(cred.PrivateKeyCiphertext)
	if err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("decrypt private key: %w", err), nil)
		return
	}
	pass, err := cp.Decrypt(cred.PassphraseCiphertext)
	if err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("decrypt passphrase: %w", err), nil)
		return
	}

	policy := remotescan.HostKeyPolicy{
		Get: func(addr string) ([]byte, error) {
			return w.store.GetRemoteHostKey(ctx, addr, task.CredentialID)
		},
		Put: func(addr string, k []byte) error {
			return w.store.PutRemoteHostKey(ctx, addr, task.CredentialID, k)
		},
	}
	inv, err := remotescan.Collect(ctx, task.Address, remotescan.Credential{
		ID:         cred.ID,
		Name:       cred.Name,
		Username:   cred.Username,
		AuthType:   cred.AuthType,
		Password:   string(pwd),
		PrivateKey: string(key),
		Passphrase: string(pass),
	}, policy, remotescan.Options{TimeoutSeconds: cfg.TimeoutSeconds})
	if err != nil {
		w.finishRemoteTask(ctx, task, err, nil)
		return
	}

	agentID := store.RemoteAgentID(task.Address)
	if err := w.store.UpsertRemoteAgent(ctx, agentID, inv.Hostname, task.Address, inv.OS, inv.Version, inv.Arch, cred.TenantID); err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("upsert remote agent: %w", err), nil)
		return
	}
	snap := &store.AssetSnapshot{
		AgentID:   agentID,
		Mode:      "FULL",
		Assets:    remoteAssetsJSON(inv),
		CreatedAt: time.Now(),
	}
	if err := w.store.UpsertAssetSnapshot(ctx, snap); err != nil {
		w.finishRemoteTask(ctx, task, fmt.Errorf("upsert remote snapshot: %w", err), nil)
		return
	}
	if err := w.store.UpsertRemoteHost(ctx, store.RemoteHost{
		Address:      task.Address,
		CredentialID: task.CredentialID,
		Hostname:     inv.Hostname,
		OSType:       inv.OS,
		OSVersion:    inv.Version,
		Arch:         inv.Arch,
		PackageCount: len(inv.Assets),
	}); err != nil {
		slog.Error("upsert remote host failed", "task_id", task.ID, "error", err)
	}
	w.TriggerMatch(agentID)
	w.finishRemoteTask(ctx, task, nil, map[string]interface{}{
		"hostname":    inv.Hostname,
		"os":          inv.OS,
		"version":     inv.Version,
		"assets":      len(inv.Assets),
		"duration_ms": time.Since(start).Milliseconds(),
	})
}

// finishRemoteTask marks the task done/failed and appends one audit entry.
// Credential material never appears in the audit detail.
func (w *Worker) finishRemoteTask(ctx context.Context, task store.RemoteScanTask, scanErr error, summary map[string]interface{}) {
	errText := ""
	status := 200
	taskStatus := "done"
	if scanErr != nil {
		errText = scanErr.Error()
		status = 400
		taskStatus = "failed"
		slog.Warn("remote scan failed", "task_id", task.ID, "address", task.Address, "error", errText)
	}
	data, _ := json.Marshal(summary)
	if err := w.store.CompleteRemoteScanTask(ctx, task.ID, errText, data); err != nil {
		slog.Error("complete remote scan task failed", "task_id", task.ID, "error", err)
	}
	detail, _ := json.Marshal(map[string]interface{}{
		"task_id":       task.ID,
		"credential_id": task.CredentialID,
		"address":       task.Address,
		"status":        taskStatus,
		"error":         errText,
	})
	if err := w.store.AppendAuditLog(ctx, store.AuditLog{
		Actor:      task.CreatedBy,
		Method:     "REMOTE_SCAN",
		Path:       "/api/v1/remote/scan",
		Status:     status,
		DurationMS: 0,
		Detail:     detail,
	}); err != nil {
		slog.Error("append remote scan audit failed", "task_id", task.ID, "error", err)
	}
}

// remoteAssetsJSON wraps the inventory assets in the shape the matcher
// expects ({"assets": [...]}).
func remoteAssetsJSON(inv *remotescan.Inventory) []byte {
	data, _ := json.Marshal(map[string]interface{}{"assets": inv.Assets})
	return data
}

// ConfigureReporting wires the optional scheduled report into the worker.
func (w *Worker) ConfigureReporting(cfg *report.Config, smtp *alert.SMTPConfig) {
	w.reportCfg = cfg
	w.reportSMTP = smtp
}

// ConfigureAuditRetention enables periodic deletion of audit entries older
// than the given number of days. A non-positive value disables cleanup.
func (w *Worker) ConfigureAuditRetention(days int) {
	if days > 0 {
		w.auditRetention = time.Duration(days) * 24 * time.Hour
	}
}

func (w *Worker) Stop() {
	close(w.done)
}

// TriggerMatch enqueues one coalesced single-agent match job.
func (w *Worker) TriggerMatch(agentID string) {
	w.enqueue("match_agent", agentID, map[string]interface{}{"agent_id": agentID})
}

func (w *Worker) RefreshFeeds(ctx context.Context) {
	agents := w.collectAgentSummaries(ctx)
	go w.loader.RefreshAllNVD(context.Background(), agents)
	go w.loader.RefreshAllOSV(context.Background(), agents)
	go w.loader.RefreshRedHat(context.Background(), agents)
}

// feedLoop runs on the "feed" lease holder: it mirrors custom intel, loads
// the recent MSRC feed, marks the cross-instance feed-ready state, and then
// keeps every external feed refreshed on its own cadence.
func (w *Worker) feedLoop(ctx context.Context) {
	slog.Info("feed: syncing custom intel...")
	if err := w.loader.SyncCustomIntel(ctx); err != nil {
		slog.Error("feed: custom intel sync failed", "error", err)
	}
	slog.Info("feed: loading recent MSRC (last 12 months)...")
	if err := w.loader.LoadMSRCAll(ctx); err != nil {
		slog.Error("feed: recent msrc load failed", "error", err)
	} else if err := w.loader.SyncKBMetadata(ctx); err != nil {
		slog.Error("feed: kb metadata sync failed", "error", err)
	}
	go validateKBLinks(context.Background(), w.store)
	go resolveActiveKBDownloads(context.Background(), w.store, patch.NewCatalogResolver())
	if err := w.store.SetWorkerState(ctx, "feed_ready", true); err != nil {
		slog.Error("feed: feed_ready marker failed", "error", err)
	}
	slog.Info("feed: recent MSRC loaded, match can start now")

	go func() {
		slog.Info("feed: loading historical MSRC in background...")
		w.loader.LoadMSRCHistorical(context.Background())
		if err := w.loader.SyncKBMetadata(context.Background()); err != nil {
			slog.Error("feed: historical kb metadata sync failed", "error", err)
		}
		validateKBLinks(context.Background(), w.store)
		resolveActiveKBDownloads(context.Background(), w.store, patch.NewCatalogResolver())
	}()

	go func() {
		slog.Info("feed: preloading NVD for all agents...")
		agents := w.collectAgentSummaries(context.Background())
		w.loader.RefreshAllNVD(context.Background(), agents)
	}()

	go func() {
		slog.Info("feed: preloading OSV for all agents...")
		agents := w.collectAgentSummaries(context.Background())
		w.loader.RefreshAllOSV(context.Background(), agents)
	}()

	go func() {
		slog.Info("feed: preloading Debian tracker...")
		agents := w.collectAgentSummaries(context.Background())
		w.loader.RefreshDebianTracker(context.Background(), agents)
	}()

	go func() {
		slog.Info("feed: preloading Red Hat CVE data...")
		agents := w.collectAgentSummaries(context.Background())
		w.loader.RefreshRedHat(context.Background(), agents)
	}()

	go func() {
		slog.Info("feed: loading EPSS/KEV intel...")
		if err := w.loader.RefreshIntel(context.Background()); err != nil {
			slog.Error("feed: intel refresh failed", "error", err)
		}
		if _, err := w.store.RecalcAllRisk(context.Background()); err != nil {
			slog.Error("feed: initial risk recalc failed", "error", err)
		}
	}()

	refreshTicker := time.NewTicker(w.feedCfg.MSRCRefresh)
	nvdTicker := time.NewTicker(w.feedCfg.NVDRefresh)
	osvTicker := time.NewTicker(w.feedCfg.OSVRefresh)
	debianTicker := time.NewTicker(w.feedCfg.DebianRefresh)
	redhatTicker := time.NewTicker(w.feedCfg.RedHatRefresh)
	intelTicker := time.NewTicker(24 * time.Hour)
	kbLinkTicker := time.NewTicker(6 * time.Hour)
	defer refreshTicker.Stop()
	defer nvdTicker.Stop()
	defer osvTicker.Stop()
	defer debianTicker.Stop()
	defer redhatTicker.Stop()
	defer intelTicker.Stop()
	defer kbLinkTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-refreshTicker.C:
			if err := w.loader.RefreshMSRCCurrent(ctx); err != nil {
				slog.Error("feed: msrc current refresh failed", "error", err)
			} else if err := w.loader.SyncKBMetadata(ctx); err != nil {
				slog.Error("feed: kb metadata sync failed", "error", err)
			}
			validateKBLinks(ctx, w.store)
		case <-nvdTicker.C:
			agents := w.collectAgentSummaries(ctx)
			go w.loader.RefreshAllNVD(context.Background(), agents)
		case <-osvTicker.C:
			agents := w.collectAgentSummaries(ctx)
			go w.loader.RefreshAllOSV(context.Background(), agents)
		case <-debianTicker.C:
			agents := w.collectAgentSummaries(ctx)
			go w.loader.RefreshDebianTracker(context.Background(), agents)
		case <-redhatTicker.C:
			agents := w.collectAgentSummaries(ctx)
			go w.loader.RefreshRedHat(context.Background(), agents)
		case <-intelTicker.C:
			if err := w.RefreshIntel(ctx); err != nil {
				slog.Error("feed: intel refresh failed", "error", err)
			}
		case <-kbLinkTicker.C:
			validateKBLinks(ctx, w.store)
			resolveActiveKBDownloads(ctx, w.store, patch.NewCatalogResolver())
		}
	}
}

func (w *Worker) collectAgentSummaries(ctx context.Context) []cve.AgentSnapshotSummary {
	list, err := w.store.ListAgents(ctx, nil)
	if err != nil {
		return nil
	}
	var summaries []cve.AgentSnapshotSummary
	for _, ag := range list {
		snap, err := w.store.GetAssetSnapshot(ctx, ag.ID)
		if err != nil || snap == nil {
			continue
		}
		summaries = append(summaries, cve.AgentSnapshotSummary{
			AgentID:   ag.ID,
			OSType:    ag.OSType,
			OSVersion: ag.OSVersion,
			Assets:    snap.Assets,
		})
	}
	return summaries
}

// matchCycleLoop runs the full-match cycle on the "match" lease holder.
// Per-agent jobs are handled in parallel by every worker's matchJobLoop.
func (w *Worker) matchCycleLoop(ctx context.Context) {
	if !w.waitFeedReady(ctx) {
		return
	}
	w.RunMatchCycle(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.RunMatchCycle(ctx)
		}
	}
}

func (w *Worker) runSingleMatch(ctx context.Context, agentID string) {
	if agentID == "" {
		return
	}

	agent, err := w.store.GetAgent(ctx, agentID)
	if err != nil || agent == nil || agent.Status != "online" {
		return
	}

	snap, err := w.store.GetAssetSnapshot(ctx, agentID)
	if err != nil || snap == nil {
		return
	}

	assets := cve.AssetsFromJSON(snap.Assets)
	if len(assets) == 0 {
		return
	}

	installedKBs := make(map[string]bool)
	for _, a := range assets {
		if a.Format == "hotfix" {
			installedKBs[a.Name] = true
		}
	}

	results, err := w.match.Match(ctx, agentID, assets, installedKBs)
	if err != nil {
		slog.Error("match failed", "agent_id", agentID, "error", err)
		return
	}

	slog.Info("match completed", "agent_id", agentID, "assets", len(assets), "cves", len(results))

	saveErr := w.match.SaveResults(ctx, agentID, results)
	if saveErr != nil {
		slog.Error("save results failed", "agent_id", agentID, "error", saveErr)
	}
	if _, err := w.store.RecalcAgentRisk(ctx, agentID); err != nil {
		slog.Warn("risk recalc failed", "agent_id", agentID, "error", err)
	}
	if w.alerts != nil && w.alerts.Enabled() {
		alertResults := make([]alert.Result, 0, len(results))
		for _, r := range results {
			alertResults = append(alertResults, alert.Result{
				CVEID:     r.CVEID,
				AssetName: r.AssetName,
				Severity:  r.Severity,
				Source:    r.Source,
				CVSSScore: r.CVSSScore,
				Status:    r.MatchStatus,
			})
		}
		if err := w.alerts.Evaluate(ctx, agentID, alertResults); err != nil {
			slog.Error("alert evaluation failed", "agent_id", agentID, "error", err)
		}
	}
	if saveErr == nil {
		if err := w.store.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
			slog.Error("post-patch verification failed", "agent_id", agentID, "error", err)
		}
	}
}

// RefreshIntel triggers an EPSS/KEV refresh and a full risk recalculation.
// It is serialized across instances by a job_queue claim.
func (w *Worker) RefreshIntel(ctx context.Context) error {
	jobID, inserted, err := w.store.EnqueueJob(ctx, "intel_refresh", "", nil)
	if err != nil {
		return err
	}
	if !inserted {
		return errors.New("intel refresh is already running")
	}
	if err := w.loader.RefreshIntel(ctx); err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return err
	}
	if _, err := w.store.RecalcAllRisk(ctx); err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return err
	}
	return w.store.FinishJob(ctx, jobID, "")
}

// RunMatchCycle runs one full matching pass over all online agents. It is
// serialized across instances by a job_queue claim.
func (w *Worker) RunMatchCycle(ctx context.Context) {
	jobID, inserted, err := w.store.EnqueueJob(ctx, "match_full", "", nil)
	if err != nil {
		slog.Error("match: enqueue full cycle failed", "error", err)
		return
	}
	if !inserted {
		slog.Info("match cycle skipped, already running")
		return
	}
	defer func() {
		if err := w.store.FinishJob(ctx, jobID, ""); err != nil {
			slog.Error("match: finish job failed", "job_id", jobID, "error", err)
		}
	}()

	slog.Info("match cycle started")

	agents, err := w.store.ListAgents(ctx, nil)
	if err != nil {
		slog.Error("match: list agents failed", "error", err)
		return
	}
	slog.Info("match: agents found", "count", len(agents))

	for _, agent := range agents {
		if agent.Status != "online" {
			continue
		}
		hasPolicy, _ := w.store.HasEnabledScanPolicy(ctx, agent.ID)
		if hasPolicy {
			continue
		}
		w.runSingleMatch(ctx, agent.ID)
	}

	slog.Info("match cycle completed")
}

func (w *Worker) scanPolicyLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			due, err := w.store.DueScanPolicies(ctx)
			if err != nil {
				slog.Warn("scan policy due query failed", "error", err)
				continue
			}
			for _, p := range due {
				w.TriggerMatch(p.AgentID)
				if err := w.store.BumpScanPolicyNextRun(ctx, p.AgentID, p.IntervalMinutes); err != nil {
					slog.Warn("scan policy bump failed", "agent_id", p.AgentID, "error", err)
				}
				slog.Info("scan policy triggered", "agent_id", p.AgentID,
					"interval_minutes", p.IntervalMinutes)
			}
		}
	}
}

// slaLoop periodically checks for vulnerabilities past their SLA deadline
// and creates/refreshes sla-breach alerts through the alert pipeline.
func (w *Worker) slaLoop(ctx context.Context) {
	if w.alerts == nil || !w.alerts.Enabled() {
		return
	}
	if err := w.alerts.EnsureDefaultRules(ctx); err != nil {
		slog.Error("sla: default rules seeding failed", "error", err)
	}
	run := func() {
		if _, err := w.alerts.CheckSLA(ctx); err != nil {
			slog.Error("sla: check failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(w.alerts.SLACheckInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			run()
		}
	}
}

func (w *Worker) archiveLoop(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			n, err := w.store.ArchiveStaleAgents(ctx, 90*24*time.Hour)
			if err != nil {
				slog.Error("archive agents failed", "error", err)
			} else if n > 0 {
				slog.Info("archived stale agents", "count", n)
			}
			if cleaned, err := w.store.CleanupFinishedJobs(ctx, 24*time.Hour); err != nil {
				slog.Warn("cleanup finished jobs failed", "error", err)
			} else if cleaned > 0 {
				slog.Info("cleaned finished jobs", "count", cleaned)
			}
			if w.auditRetention > 0 {
				cleaned, err := w.store.DeleteAuditLogsOlderThan(ctx, w.auditRetention)
				if err != nil {
					slog.Warn("cleanup audit logs failed", "error", err)
				} else if cleaned > 0 {
					slog.Info("cleaned audit logs", "count", cleaned)
				}
			}
		}
	}
}
