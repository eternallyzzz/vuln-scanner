package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vuln-scanner/internal/cloudscan"
	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/store"
)

// cloudLoop checks due accounts every 30s and also reacts to manual refresh
// jobs enqueued by the REST API.
func (w *Worker) cloudLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	slog.Info("cloud loop started",
		"concurrency", w.cloudCfg.Concurrency,
		"default_refresh_interval_minutes", w.cloudCfg.DefaultRefreshIntervalMinutes)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		w.processCloudJobs(ctx)
	}
}

func (w *Worker) processCloudJobs(ctx context.Context) {
	due, err := w.store.ClaimCloudAccountsDue(ctx, time.Now(), w.workerID, store.StaleClaimLease)
	if err != nil {
		slog.Error("cloud due accounts lookup failed", "error", err)
		return
	}
	jobs, err := w.store.ClaimJobs(ctx, []string{"cloud_refresh"}, w.workerID, 16)
	if err != nil {
		slog.Error("cloud refresh jobs lookup failed", "error", err)
	}
	sem := make(chan struct{}, w.cloudCfg.Concurrency)
	for i := range due {
		sem <- struct{}{}
		go func(a store.CloudAccount) {
			defer func() { <-sem }()
			w.refreshCloudAccount(context.Background(), a.ID)
		}(due[i])
	}
	for _, j := range jobs {
		var payload struct {
			AccountID int64 `json:"account_id"`
		}
		_ = json.Unmarshal(j.Payload, &payload)
		sem <- struct{}{}
		go func(j store.Job) {
			defer func() { <-sem }()
			if payload.AccountID > 0 {
				w.refreshCloudAccount(context.Background(), payload.AccountID)
			}
			if err := w.store.FinishJob(context.Background(), j.ID, ""); err != nil {
				slog.Error("finish cloud refresh job failed", "job_id", j.ID, "error", err)
			}
		}(j)
	}
}

func (w *Worker) refreshCloudAccount(ctx context.Context, accountID int64) {
	account, err := w.store.GetCloudAccount(ctx, accountID)
	if err != nil {
		slog.Error("cloud account lookup failed", "account_id", accountID, "error", err)
		return
	}
	if !account.Enabled {
		return
	}
	cipher, err := remotescan.NewCipher(w.cloudKey)
	if err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	plain, err := cipher.Decrypt(account.CredentialCiphertext)
	if err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	var cred cloudscan.Credentials
	if err := json.Unmarshal(plain, &cred); err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	client, err := cloudscan.NewClient(cred, account.Regions, w.cloudCfg.Timeout())
	if err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	resources, err := client.Discover(ctx)
	if err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	if err := w.store.UpsertCloudResources(ctx, account.ID, account.AccountID, account.Provider, resources); err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	if err := w.store.SyncCloudCMDB(ctx, *account, resources); err != nil {
		w.finishCloudRefresh(ctx, account, err, nil)
		return
	}
	w.finishCloudRefresh(ctx, account, nil, map[string]interface{}{
		"account_id": account.ID,
		"provider":   account.Provider,
		"resources":  len(resources),
	})
}

func (w *Worker) finishCloudRefresh(ctx context.Context, account *store.CloudAccount, refreshErr error, summary map[string]interface{}) {
	errText := ""
	status := 200
	if refreshErr != nil {
		errText = refreshErr.Error()
		status = 500
		slog.Warn("cloud refresh failed", "account_id", account.ID,
			"provider", account.Provider, "error", errText)
	}
	if err := w.store.MarkCloudAccountRefreshed(ctx, account.ID, errText); err != nil {
		slog.Error("mark cloud refresh failed", "account_id", account.ID, "error", err)
	}
	detail, _ := json.Marshal(map[string]interface{}{
		"account_id": account.ID,
		"provider":   account.Provider,
		"name":       account.Name,
		"error":      errText,
		"summary":    summary,
	})
	if err := w.store.AppendAuditLog(ctx, store.AuditLog{
		Actor:      "cloud-worker",
		Method:     "POST",
		Path:       "internal/cloud/refresh",
		Status:     status,
		DurationMS: 0,
		Detail:     detail,
	}); err != nil {
		slog.Warn("append cloud audit failed", "account_id", account.ID, "error", err)
	}
}
