package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/store"
)

type containerScanState struct {
	Running       bool
	LastRun       *time.Time
	NextRun       *time.Time
	ImagesScanned int
	VulnsTotal    int64
	LastError     string
}

// ConfigureContainerScanning enables the periodic container scan loop. It
// must be called before Worker.Start.
func (w *Worker) ConfigureContainerScanning(cfg *container.Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	w.containerCfg = cfg
	w.containerScanner = container.NewScanner(cfg)
}

func (w *Worker) TriggerContainerScan() {
	if w.containerCfg == nil {
		return
	}
	w.enqueue("container_scan", "", nil)
}

func (w *Worker) containerScanLoop(ctx context.Context) {
	cfg := w.containerCfg
	if cfg == nil || !cfg.Enabled {
		return
	}
	slog.Info("container scan loop started",
		"interval_minutes", cfg.ScanIntervalMinutes, "agent_id", cfg.AgentID)

	interval := time.Duration(cfg.ScanIntervalMinutes) * time.Minute
	w.runContainerScan(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.runContainerScan(ctx)
		case <-w.wakeCh:
			jobs, err := w.store.ClaimJobs(ctx, []string{"container_scan"}, w.workerID, 1)
			if err != nil {
				slog.Error("claim container scan jobs failed", "error", err)
				continue
			}
			for _, j := range jobs {
				w.runContainerScan(ctx)
				if err := w.store.FinishJob(ctx, j.ID, ""); err != nil {
					slog.Error("finish container scan job failed", "job_id", j.ID, "error", err)
				}
			}
		}
	}
}

func (w *Worker) runContainerScan(ctx context.Context) {
	cfg := w.containerCfg
	if cfg == nil || !cfg.Enabled {
		return
	}
	w.containerMu.Lock()
	if w.containerState.Running {
		w.containerMu.Unlock()
		return
	}
	w.containerState.Running = true
	w.containerState.LastError = ""
	w.containerMu.Unlock()

	start := time.Now()
	agentID := cfg.AgentID
	var lastErr error
	defer func() {
		w.containerMu.Lock()
		w.containerState.Running = false
		w.containerState.LastRun = &start
		next := start.Add(time.Duration(cfg.ScanIntervalMinutes) * time.Minute)
		w.containerState.NextRun = &next
		w.containerState.LastError = ""
		if lastErr != nil {
			w.containerState.LastError = lastErr.Error()
		}
		w.containerMu.Unlock()
	}()

	if err := w.store.UpsertContainerAgent(ctx, agentID, cfg.AgentHostname, "docker", "amd64", cfg.TenantID); err != nil {
		lastErr = fmt.Errorf("upsert container agent: %w", err)
		slog.Error("container scan: agent upsert failed", "error", err)
		return
	}
	images, err := w.containerScanner.ListImages(ctx)
	if err != nil {
		lastErr = fmt.Errorf("list images: %w", err)
		slog.Error("container scan: list images failed", "error", err)
		return
	}
	images = container.FilterImages(images, cfg)
	slog.Info("container scan started", "images", len(images))

	scanned := 0
	var allResults []alert.Result
	for _, img := range images {
		ref := img.Ref()
		findings, err := w.containerScanner.ScanImage(ctx, ref)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", ref, err)
			slog.Warn("container scan image failed", "image", ref, "error", err)
			continue
		}
		version := img.Version()
		if err := w.store.UpsertContainerAsset(ctx, agentID, ref, version, cfg.DockerHost); err != nil {
			lastErr = fmt.Errorf("%s: asset upsert: %w", ref, err)
			slog.Warn("container scan asset upsert failed", "image", ref, "error", err)
			continue
		}
		results := make([]*store.CVEResult, 0, len(findings))
		for _, f := range findings {
			summary := f.PkgName + "@" + f.InstalledVersion
			if f.Title != "" {
				summary += " - " + f.Title
			}
			results = append(results, &store.CVEResult{
				CVEID: f.VulnerabilityID, AssetName: ref, AssetVersion: version,
				FixedVersion: f.FixedVersion, Severity: f.Severity,
				CVSSScore: f.CVSSScore, Summary: summary, Source: "trivy", Status: "active",
			})
			allResults = append(allResults, alert.Result{
				CVEID: f.VulnerabilityID, AssetName: ref, Severity: f.Severity,
				Source: "trivy", CVSSScore: f.CVSSScore, Status: "active",
			})
		}
		if err := w.store.ReplaceContainerVulns(ctx, agentID, ref, results); err != nil {
			lastErr = fmt.Errorf("%s: vuln replace: %w", ref, err)
			slog.Warn("container scan vuln replace failed", "image", ref, "error", err)
			continue
		}
		scanned++
		slog.Info("container scan image done", "image", ref, "findings", len(findings))
	}

	vulns, err := w.store.GetContainerVulnCount(ctx, agentID)
	if err != nil {
		lastErr = fmt.Errorf("vuln count: %w", err)
	}
	w.containerMu.Lock()
	w.containerState.ImagesScanned = scanned
	w.containerState.VulnsTotal = vulns
	w.containerMu.Unlock()

	if _, err := w.store.RecalcAgentRisk(ctx, agentID); err != nil {
		slog.Warn("container risk recalc failed", "agent_id", agentID, "error", err)
	}

	seenAlert := map[string]bool{}
	alertResults := make([]alert.Result, 0, len(allResults))
	for _, r := range allResults {
		key := r.CVEID + "|" + r.AssetName
		if seenAlert[key] {
			continue
		}
		seenAlert[key] = true
		alertResults = append(alertResults, r)
	}
	if w.alerts != nil && w.alerts.Enabled() && len(alertResults) > 0 {
		if err := w.alerts.Evaluate(ctx, agentID, alertResults); err != nil {
			slog.Warn("container alert evaluation failed", "error", err)
		}
	}
	slog.Info("container scan completed", "images_scanned", scanned,
		"vulns_total", vulns, "last_error", lastErr)
}

func (w *Worker) ContainerStatus() map[string]interface{} {
	w.containerMu.Lock()
	defer w.containerMu.Unlock()
	enabled := w.containerCfg != nil && w.containerCfg.Enabled
	agentID := ""
	if w.containerCfg != nil {
		agentID = w.containerCfg.AgentID
	}
	return map[string]interface{}{
		"enabled": enabled, "agent_id": agentID, "running": w.containerState.Running,
		"last_run": w.containerState.LastRun, "next_run": w.containerState.NextRun,
		"images_scanned": w.containerState.ImagesScanned,
		"vulns_total":    w.containerState.VulnsTotal,
		"last_error":     w.containerState.LastError,
	}
}
