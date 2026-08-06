package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vuln-scanner/internal/store"
	"vuln-scanner/internal/ticket"
)

const (
	ticketMaxCreateAttempts = 3
	ticketMaxSyncAttempts   = 3
	ticketBatchSize         = 10
)

// ticketLoop polls for alerts that need a ticket created or a status sync,
// with a short wake-up channel used by the manual retry endpoint.
func (w *Worker) ticketLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	slog.Info("ticket loop started",
		"provider", w.tickets.Config().Provider, "base_url", w.tickets.Config().BaseURL)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.ticketCh:
		}
		w.processTicketCreate(ctx)
		w.processTicketSync(ctx)
	}
}

func (w *Worker) processTicketCreate(ctx context.Context) {
	pending, err := w.store.ListTicketCreatePending(ctx, ticketBatchSize, ticketMaxCreateAttempts)
	if err != nil {
		slog.Error("ticket create pending lookup failed", "error", err)
		return
	}
	for _, d := range pending {
		ref, err := w.tickets.Create(context.Background(), ticketAlertInfo(d))
		if err != nil {
			msg := err.Error()
			if e := w.store.MarkTicketCreateFailed(context.Background(), d.ID, msg); e != nil {
				slog.Error("ticket create failure record failed", "alert_id", d.ID, "error", e)
			}
			w.appendTicketAudit(context.Background(), "internal/ticket/create", 500, map[string]interface{}{
				"alert_id": d.ID, "error": msg,
			})
			slog.Warn("ticket create failed", "alert_id", d.ID, "cve", d.CVEID, "error", msg)
			continue
		}
		if err := w.store.MarkTicketCreated(context.Background(), d.ID, ref.Provider, ref.Key, ref.URL); err != nil {
			slog.Error("ticket created marker failed", "alert_id", d.ID, "error", err)
		}
		w.appendTicketAudit(context.Background(), "internal/ticket/create", 200, map[string]interface{}{
			"alert_id": d.ID, "provider": ref.Provider, "key": ref.Key, "url": ref.URL,
		})
		slog.Info("ticket created", "alert_id", d.ID, "provider", ref.Provider,
			"key", ref.Key, "cve", d.CVEID)
	}
}

func (w *Worker) processTicketSync(ctx context.Context) {
	pending, err := w.store.ListTicketSyncPending(ctx, ticketBatchSize, ticketMaxSyncAttempts)
	if err != nil {
		slog.Error("ticket sync pending lookup failed", "error", err)
		return
	}
	for _, d := range pending {
		ref := ticket.TicketRef{
			Provider: d.TicketProvider,
			Key:      d.TicketKey,
			URL:      d.TicketURL,
		}
		err := w.tickets.Sync(context.Background(), ref, d.Status)
		if err != nil {
			msg := err.Error()
			if e := w.store.MarkTicketSyncFailed(context.Background(), d.ID, msg); e != nil {
				slog.Error("ticket sync failure record failed", "alert_id", d.ID, "error", e)
			}
			w.appendTicketAudit(context.Background(), "internal/ticket/sync", 500, map[string]interface{}{
				"alert_id": d.ID, "key": d.TicketKey, "status": d.Status, "error": msg,
			})
			slog.Warn("ticket sync failed", "alert_id", d.ID, "key", d.TicketKey,
				"status", d.Status, "error", msg)
			continue
		}
		if err := w.store.MarkTicketSynced(context.Background(), d.ID, d.Status); err != nil {
			slog.Error("ticket synced marker failed", "alert_id", d.ID, "error", err)
		}
		w.appendTicketAudit(context.Background(), "internal/ticket/sync", 200, map[string]interface{}{
			"alert_id": d.ID, "key": d.TicketKey, "status": d.Status,
		})
		slog.Info("ticket synced", "alert_id", d.ID, "key", d.TicketKey, "status", d.Status)
	}
}

func ticketAlertInfo(d store.AlertDetail) ticket.AlertInfo {
	return ticket.AlertInfo{
		AlertID:       d.ID,
		RuleName:      d.RuleName,
		AgentID:       d.AgentID,
		AgentHostname: d.AgentHostname,
		CVEID:         d.CVEID,
		AssetName:     d.AssetName,
		Severity:      d.Severity,
		CVSS:          d.CVSSScore,
		Source:        d.Source,
		DetectedAt:    d.FirstSeen,
	}
}

func (w *Worker) appendTicketAudit(ctx context.Context, path string, status int, detail map[string]interface{}) {
	data, _ := json.Marshal(detail)
	if err := w.store.AppendAuditLog(ctx, store.AuditLog{
		Actor:      "ticket-worker",
		Method:     "POST",
		Path:       path,
		Status:     status,
		DurationMS: 0,
		Detail:     data,
	}); err != nil {
		slog.Warn("append ticket audit failed", "path", path, "error", err)
	}
}
