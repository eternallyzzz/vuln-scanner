package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"vuln-scanner/internal/store"
)

const (
	loopLeaseDuration = 30 * time.Second
	loopLeaseRenew    = 10 * time.Second
	loopLeasePoll     = 5 * time.Second
)

// runLeaseLoop acquires the lease for one single-runner loop, starts it with
// a heartbeat, and releases the lease when the loop exits.
func (w *Worker) runLeaseLoop(ctx context.Context, loop string, fn func(context.Context)) {
	poll := time.NewTicker(loopLeasePoll)
	defer poll.Stop()
	for {
		ok, err := w.store.AcquireLoopLease(ctx, loop, w.workerID, w.hostname, os.Getpid(), loopLeaseDuration)
		if err != nil {
			slog.Error("lease acquire failed", "loop", loop, "error", err)
		} else if ok {
			slog.Info("loop lease acquired", "loop", loop, "worker", w.workerID)
			w.runLeasedLoop(ctx, loop, fn)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-poll.C:
		case <-w.wakeCh:
		}
	}
}

func (w *Worker) runLeasedLoop(ctx context.Context, loop string, fn func(context.Context)) {
	hbCtx, hbCancel := context.WithCancel(context.Background())
	defer hbCancel()
	go func() {
		renew := time.NewTicker(loopLeaseRenew)
		defer renew.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-renew.C:
				ok, err := w.store.RenewLoopLease(hbCtx, loop, w.workerID, loopLeaseDuration)
				if err != nil {
					slog.Error("lease renew failed", "loop", loop, "error", err)
				} else if !ok {
					slog.Warn("lease renew lost", "loop", loop, "worker", w.workerID)
				}
			}
		}
	}()
	fn(ctx)
	hbCancel()
	if err := w.store.ReleaseLoopLease(context.Background(), loop, w.workerID); err != nil {
		slog.Error("lease release failed", "loop", loop, "error", err)
	}
	slog.Info("loop lease released", "loop", loop, "worker", w.workerID)
}

// wake broadcasts a non-blocking nudge to every worker loop.
func (w *Worker) wake() {
	select {
	case w.wakeCh <- struct{}{}:
	default:
	}
}

// enqueue inserts one coalesced job and notifies the shared PostgreSQL
// channel. The per-loop tickers remain the reliability fallback.
func (w *Worker) enqueue(kind, key string, payload interface{}) {
	if w == nil || w.store == nil {
		return
	}
	_, inserted, err := w.store.EnqueueJob(context.Background(), kind, key, payload)
	if err != nil {
		slog.Warn("job enqueue failed", "kind", kind, "key", key, "error", err)
		return
	}
	if inserted {
		if err := w.store.NotifyJobs(context.Background(), kind); err != nil {
			slog.Warn("job notify failed", "kind", kind, "error", err)
		}
	}
}

// jobNotifyListener listens for pg_notify on the shared job channel and
// wakes the local loops. It reconnects on errors; polling is the fallback.
func (w *Worker) jobNotifyListener(ctx context.Context) {
	backoff := time.NewTicker(loopLeasePoll)
	defer backoff.Stop()
	for {
		conn, err := w.store.Pool().Acquire(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-w.done:
				return
			case <-backoff.C:
			}
			continue
		}
		func() {
			defer conn.Release()
			if _, err := conn.Exec(ctx, "LISTEN vulnscan_jobs"); err != nil {
				slog.Warn("job notify listen failed", "error", err)
				return
			}
			for {
				if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
					if !errors.Is(err, context.Canceled) {
						slog.Warn("job notify wait failed", "error", err)
					}
					return
				}
				w.wake()
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-backoff.C:
		}
	}
}

// jobMaintenanceLoop reclaims jobs whose claim lease expired after a crash.
func (w *Worker) jobMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			n, err := w.store.RequeueStaleJobs(ctx, store.StaleClaimLease)
			if err != nil {
				slog.Warn("requeue stale jobs failed", "error", err)
			} else if n > 0 {
				slog.Info("requeued stale jobs", "count", n)
			}
		}
	}
}

// waitFeedReady blocks until the lease-holding feed loop has populated the
// feed mirror (worker_state.feed_ready) or the context is done.
func (w *Worker) waitFeedReady(ctx context.Context) bool {
	ticker := time.NewTicker(loopLeasePoll)
	defer ticker.Stop()
	for {
		ready, err := w.store.GetWorkerStateBool(ctx, "feed_ready")
		if err == nil && ready {
			return true
		}
		if err != nil {
			slog.Warn("feed ready check failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return false
		case <-w.done:
			return false
		case <-ticker.C:
		case <-w.wakeCh:
		}
	}
}

// matchJobLoop claims single-agent match jobs on every worker.
func (w *Worker) matchJobLoop(ctx context.Context) {
	if !w.waitFeedReady(ctx) {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	slog.Info("match job loop started", "worker", w.workerID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		jobs, err := w.store.ClaimJobs(ctx, []string{"match_agent"}, w.workerID, 8)
		if err != nil {
			slog.Error("claim match jobs failed", "error", err)
			continue
		}
		for _, j := range jobs {
			var payload struct {
				AgentID string `json:"agent_id"`
			}
			if err := json.Unmarshal(j.Payload, &payload); err != nil {
				_ = w.store.FinishJob(ctx, j.ID, "invalid payload: "+err.Error())
				continue
			}
			w.runSingleMatch(ctx, payload.AgentID)
			if err := w.store.FinishJob(ctx, j.ID, ""); err != nil {
				slog.Error("finish match job failed", "job_id", j.ID, "error", err)
			}
		}
	}
}

// remediationJobLoop claims auto-remediation jobs on every worker.
func (w *Worker) remediationJobLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	slog.Info("remediation job loop started", "worker", w.workerID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		jobs, err := w.store.ClaimJobs(ctx, []string{"remediation"}, w.workerID, 4)
		if err != nil {
			slog.Error("claim remediation jobs failed", "error", err)
			continue
		}
		for _, j := range jobs {
			var req remediationRequest
			if err := json.Unmarshal(j.Payload, &req); err != nil {
				_ = w.store.FinishJob(ctx, j.ID, "invalid payload: "+err.Error())
				continue
			}
			w.processRemediation(ctx, req)
			if err := w.store.FinishJob(ctx, j.ID, ""); err != nil {
				slog.Error("finish remediation job failed", "job_id", j.ID, "error", err)
			}
		}
	}
}
