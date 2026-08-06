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
// requests from the REST API.
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
		case accountID := <-w.cloudCh:
			w.refreshCloudAccount(context.Background(), accountID)
		case <-ticker.C:
			w.refreshDueCloudAccounts(ctx)
		}
	}
}

func (w *Worker) refreshDueCloudAccounts(ctx context.Context) {
	due, err := w.store.CloudAccountsDue(ctx, time.Now())
	if err != nil {
		slog.Error("cloud due accounts lookup failed", "error", err)
		return
	}
	if len(due) == 0 {
		return
	}
	sem := make(chan struct{}, w.cloudCfg.Concurrency)
	for i := range due {
		sem <- struct{}{}
		go func(a store.CloudAccount) {
			defer func() { <-sem }()
			w.refreshCloudAccount(context.Background(), a.ID)
		}(due[i])
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
