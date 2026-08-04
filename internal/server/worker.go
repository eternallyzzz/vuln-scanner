package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

type Worker struct {
	store    *store.Store
	loader   *cve.Loader
	match    *cve.Matcher
	alerts   *alert.Service
	patchCfg *patch.Config

	done             chan struct{}
	matchCh          chan string
	remediationCh    chan remediationRequest
	rateLimiter      *hourlyLimiter
	containerCfg     *container.Config
	containerScanner *container.Scanner
	containerCh      chan struct{}
	containerMu      sync.Mutex
	containerState   containerScanState
	mu               sync.Mutex
	matching         bool
	matchPending     bool
	ready            chan struct{}
}

func NewWorker(s *store.Store, loader *cve.Loader, matcher *cve.Matcher, alerts *alert.Service, patchCfg *patch.Config) *Worker {
	w := &Worker{
		store:         s,
		loader:        loader,
		match:         matcher,
		alerts:        alerts,
		patchCfg:      patchCfg,
		done:          make(chan struct{}),
		matchCh:       make(chan string, 64),
		remediationCh: make(chan remediationRequest, 64),
		ready:         make(chan struct{}),
	}
	if patchCfg != nil && patchCfg.AutoRemediation != nil {
		w.rateLimiter = &hourlyLimiter{max: patchCfg.AutoRemediation.MaxCampaignsPerHourResolved()}
	}
	if alerts != nil {
		alerts.SetOnNewAlert(w.handleNewAlert)
	}
	return w
}

func (w *Worker) Start(ctx context.Context) {
	go w.feedLoop(ctx)
	go w.matchLoop(ctx)
	go w.archiveLoop(ctx)
	go w.scanPolicyLoop(ctx)
	go w.remediationLoop(ctx)
	go w.containerScanLoop(ctx)
	if w.alerts != nil && w.alerts.Enabled() {
		go w.alerts.RunDeliveryLoop(ctx)
	}
	go w.reapPatchLoop(ctx)
}

func (w *Worker) Stop() {
	close(w.done)
}

func (w *Worker) TriggerMatch(agentID string) {
	select {
	case w.matchCh <- agentID:
	default:
	}
}

func (w *Worker) RefreshFeeds(ctx context.Context) {
	agents := w.collectAgentSummaries(ctx)
	go w.loader.RefreshAllNVD(context.Background(), agents)
	go w.loader.RefreshAllOSV(context.Background(), agents)
	go w.loader.RefreshRedHat(context.Background(), agents)
}

func (w *Worker) feedLoop(ctx context.Context) {
	slog.Info("feed: loading recent MSRC (last 12 months)...")
	if err := w.loader.LoadMSRCAll(ctx); err != nil {
		slog.Error("feed: recent msrc load failed", "error", err)
	}
	close(w.ready)
	slog.Info("feed: recent MSRC loaded, match can start now")

	go func() {
		slog.Info("feed: loading historical MSRC in background...")
		w.loader.LoadMSRCHistorical(context.Background())
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

	refreshTicker := time.NewTicker(1 * time.Hour)
	nvdTicker := time.NewTicker(3 * time.Hour)
	osvTicker := time.NewTicker(6 * time.Hour)
	debianTicker := time.NewTicker(6 * time.Hour)
	redhatTicker := time.NewTicker(24 * time.Hour)
	intelTicker := time.NewTicker(24 * time.Hour)
	defer refreshTicker.Stop()
	defer nvdTicker.Stop()
	defer osvTicker.Stop()
	defer debianTicker.Stop()
	defer redhatTicker.Stop()
	defer intelTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-refreshTicker.C:
			if err := w.loader.RefreshMSRCCurrent(ctx); err != nil {
				slog.Error("feed: msrc current refresh failed", "error", err)
			}
		case <-nvdTicker.C:
			agents := w.collectAgentSummaries(ctx)
			w.loader.RefreshExpiredNVD(ctx)
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
			if err := w.loader.RefreshIntel(ctx); err != nil {
				slog.Error("feed: intel refresh failed", "error", err)
			}
			if _, err := w.store.RecalcAllRisk(ctx); err != nil {
				slog.Error("feed: risk recalc failed", "error", err)
			}
		}
	}
}

func (w *Worker) collectAgentSummaries(ctx context.Context) []cve.AgentSnapshotSummary {
	list, err := w.store.ListAgents(ctx)
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

func (w *Worker) matchLoop(ctx context.Context) {
	slog.Info("match loop waiting for feed ready")
	select {
	case <-w.ready:
		slog.Info("match loop: feed ready")
	case <-ctx.Done():
		return
	case <-w.done:
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
		case agentID := <-w.matchCh:
			w.runSingleMatch(ctx, agentID)
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

	if err := w.match.SaveResults(ctx, agentID, results); err != nil {
		slog.Error("save results failed", "agent_id", agentID, "error", err)
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
}

// RefreshIntel triggers an EPSS/KEV refresh and a full risk recalculation.
func (w *Worker) RefreshIntel(ctx context.Context) error {
	if err := w.loader.RefreshIntel(ctx); err != nil {
		return err
	}
	_, err := w.store.RecalcAllRisk(ctx)
	return err
}

func (w *Worker) RunMatchCycle(ctx context.Context) {
	w.mu.Lock()
	if w.matching {
		w.mu.Unlock()
		slog.Info("match cycle skipped, previous still running")
		return
	}
	w.matching = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.matching = false
		pending := w.matchPending
		w.matchPending = false
		w.mu.Unlock()
		if pending {
			w.TriggerMatch("")
		}
	}()

	slog.Info("match cycle started")

	agents, err := w.store.ListAgents(ctx)
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
		}
	}
}
