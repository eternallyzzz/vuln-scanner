package server

import (
	"context"
	"log/slog"
	"time"

	"vuln-scanner/internal/eol"
)

const eolRefreshInterval = 6 * time.Hour

// eolLoop re-evaluates every agent's OS lifecycle on startup and then every
// 6 hours, recalculating risk scores afterwards because EOL posture feeds
// into RiskScore.
func (w *Worker) eolLoop(ctx context.Context) {
	updated, err := w.refreshAllEOL(ctx)
	if err != nil {
		slog.Error("eol: initial refresh failed", "error", err)
	} else {
		slog.Info("eol: initial refresh completed", "updated", updated)
	}
	if _, err := w.store.RecalcAllRisk(ctx); err != nil {
		slog.Error("eol: initial risk recalc failed", "error", err)
	}
	ticker := time.NewTicker(eolRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			updated, err := w.refreshAllEOL(ctx)
			if err != nil {
				slog.Error("eol: refresh failed", "error", err)
				continue
			}
			slog.Info("eol: refresh completed", "updated", updated)
			if _, err := w.store.RecalcAllRisk(ctx); err != nil {
				slog.Error("eol: risk recalc failed", "error", err)
			}
		}
	}
}

func (w *Worker) refreshAllEOL(ctx context.Context) (int, error) {
	lifecycle, err := w.store.LoadOSLifecycle(ctx)
	if err != nil {
		return 0, err
	}
	agents, err := w.store.ListAgents(ctx, nil)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	for _, a := range agents {
		product, cycle := eol.NormalizeOS(a.OSType, a.OSVersion)
		st := eol.Evaluate(product, cycle, lifecycle, now)
		if err := w.store.UpdateAgentEOL(ctx, a.ID, st.State, st.Product, st.Cycle, st.EOLDate); err != nil {
			return 0, err
		}
	}
	return len(agents), nil
}

// RefreshEOL forces an EOL re-evaluation and risk recalculation.
func (w *Worker) RefreshEOL(ctx context.Context) (int, error) {
	updated, err := w.refreshAllEOL(ctx)
	if err != nil {
		return 0, err
	}
	if _, err := w.store.RecalcAllRisk(ctx); err != nil {
		return 0, err
	}
	return updated, nil
}
