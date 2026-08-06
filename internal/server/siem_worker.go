package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vuln-scanner/internal/siem"
	"vuln-scanner/internal/store"
)

// siemLoop drains the outbox on an interval (plus manual wake-ups) and
// delivers batches to every configured target.
func (w *Worker) siemLoop(ctx context.Context) {
	interval := time.Duration(w.siem.Config().DeliveryIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("siem loop started", "interval_seconds", w.siem.Config().DeliveryIntervalSeconds)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		w.processSiem(ctx)
	}
}

func (w *Worker) processSiem(ctx context.Context) {
	batchSize := w.siem.Config().BatchSize
	events, err := w.store.ClaimSiemEvents(ctx, batchSize, w.workerID, store.StaleClaimLease)
	if err != nil {
		slog.Error("siem pending lookup failed", "error", err)
		return
	}
	if len(events) == 0 {
		return
	}
	outbound := make([]siem.Event, 0, len(events))
	for _, e := range events {
		outbound = append(outbound, siem.Event{
			ID:         e.DedupeKey,
			EventType:  e.EventType,
			OccurredAt: e.CreatedAt,
			Payload:    e.Payload,
		})
	}
	if err := w.siem.SendBatch(context.Background(), outbound); err != nil {
		msg := err.Error()
		for _, e := range events {
			if markErr := w.store.MarkSiemEventFailed(context.Background(), e.ID, w.workerID, msg, w.siem.Config().MaxAttempts); markErr != nil {
				slog.Error("siem failure marker failed", "event_id", e.ID, "error", markErr)
			}
		}
		w.appendSiemAudit(context.Background(), 500, map[string]interface{}{
			"events": len(events), "error": msg,
		})
		slog.Warn("siem batch delivery failed", "events", len(events), "error", msg)
		return
	}
	for _, e := range events {
		if err := w.store.MarkSiemEventSent(context.Background(), e.ID, w.workerID); err != nil {
			slog.Error("siem sent marker failed", "event_id", e.ID, "error", err)
		}
	}
	w.appendSiemAudit(context.Background(), 200, map[string]interface{}{
		"events": len(events),
	})
	slog.Info("siem batch delivered", "events", len(events))
}

func (w *Worker) appendSiemAudit(ctx context.Context, status int, detail map[string]interface{}) {
	data, _ := json.Marshal(detail)
	if err := w.store.AppendAuditLog(ctx, store.AuditLog{
		Actor:      "siem-worker",
		Method:     "POST",
		Path:       "internal/siem/send",
		Status:     status,
		DurationMS: 0,
		Detail:     data,
	}); err != nil {
		slog.Warn("append siem audit failed", "error", err)
	}
}
