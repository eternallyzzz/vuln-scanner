package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/store"
	"vuln-scanner/internal/webdbscan"
)

// webdbLoop polls pending web/database scan tasks every 10 seconds and also
// reacts to manual triggers from the REST API.
func (w *Worker) webdbLoop(ctx context.Context) {
	cfg := w.webdbCfg
	if cfg == nil || !cfg.Enabled {
		return
	}
	sem := make(chan struct{}, cfg.Concurrency)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	slog.Info("webdb scan loop started", "concurrency", cfg.Concurrency)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		tasks, err := w.store.ClaimWebDBScanTasks(ctx, cfg.Concurrency)
		if err != nil {
			slog.Error("claim webdb scan tasks failed", "error", err)
			continue
		}
		for _, t := range tasks {
			sem <- struct{}{}
			go func(t store.WebDBTask) {
				defer func() { <-sem }()
				w.runWebDBTask(context.Background(), t, cfg)
			}(t)
		}
	}
}

func (w *Worker) runWebDBTask(ctx context.Context, task store.WebDBTask, cfg *webdbscan.Config) {
	start := time.Now()
	var cred *webdbscan.Credential
	if task.CredentialID > 0 {
		c, err := w.store.GetWebDBCredential(ctx, task.CredentialID)
		if err != nil {
			w.finishWebDBTask(ctx, task, err, nil)
			return
		}
		if c.RevokedAt != nil {
			w.finishWebDBTask(ctx, task, errors.New("credential revoked"), nil)
			return
		}
		cp, err := remotescan.NewCipher(w.webdbKey)
		if err != nil {
			w.finishWebDBTask(ctx, task, errors.New("init credential cipher: "+err.Error()), nil)
			return
		}
		plain, err := cp.Decrypt(c.PasswordCiphertext)
		if err != nil {
			w.finishWebDBTask(ctx, task, errors.New("decrypt credential: "+err.Error()), nil)
			return
		}
		cred = &webdbscan.Credential{Username: c.Username, Password: string(plain)}
	}

	var (
		agentID  string
		products []webdbscan.Product
		detail   []byte
		title    string
	)
	switch task.Kind {
	case "web":
		res, err := webdbscan.ScanWeb(ctx, task.Target, cred, *cfg)
		if err != nil {
			w.finishWebDBTask(ctx, task, err, nil)
			return
		}
		agentID = store.WebAgentID("web", task.Target)
		products = res.Products
		title = res.Title
		detail, _ = json.Marshal(res)
	case "db":
		res, err := webdbscan.ScanDB(ctx, task.Target, task.DBType, cred, *cfg)
		if err != nil {
			w.finishWebDBTask(ctx, task, err, nil)
			return
		}
		agentID = store.WebAgentID("db", task.Target)
		products = res.Products
		detail, _ = json.Marshal(res)
	default:
		w.finishWebDBTask(ctx, task, errors.New("unknown task kind "+task.Kind), nil)
		return
	}

	assets := webDBAssetsJSON(task.Kind, task.Target, products)
	if err := w.store.UpsertWebDBAgent(ctx, agentID, task.Target); err != nil {
		w.finishWebDBTask(ctx, task, errors.New("upsert webdb agent: "+err.Error()), nil)
		return
	}
	snap := &store.AssetSnapshot{
		AgentID:   agentID,
		Mode:      "FULL",
		Assets:    assets,
		CreatedAt: time.Now(),
	}
	if err := w.store.UpsertAssetSnapshot(ctx, snap); err != nil {
		w.finishWebDBTask(ctx, task, errors.New("upsert webdb snapshot: "+err.Error()), nil)
		return
	}
	if _, err := w.store.SyncCMDBFromSnapshot(ctx, agentID, assets, true); err != nil {
		slog.Warn("webdb cmdb sync failed", "task_id", task.ID, "error", err)
	}
	if err := w.store.UpsertWebDBTarget(ctx, store.WebDBTarget{
		Kind:         task.Kind,
		Target:       task.Target,
		DBType:       task.DBType,
		CredentialID: task.CredentialID,
		AgentID:      agentID,
		Status:       "active",
		Title:        title,
		Detail:       detail,
	}); err != nil {
		slog.Warn("upsert webdb target failed", "task_id", task.ID, "error", err)
	}
	w.TriggerMatch(agentID)
	summary := map[string]interface{}{
		"kind":        task.Kind,
		"target":      task.Target,
		"products":    len(products),
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if task.Kind == "db" {
		summary["db_type"] = task.DBType
	}
	w.finishWebDBTask(ctx, task, nil, summary)
}

// finishWebDBTask marks the task done/failed and appends one audit entry.
// Credential material never appears in the audit detail.
func (w *Worker) finishWebDBTask(ctx context.Context, task store.WebDBTask, scanErr error, summary map[string]interface{}) {
	errText := ""
	status := 200
	taskStatus := "done"
	if scanErr != nil {
		errText = scanErr.Error()
		status = 400
		taskStatus = "failed"
		slog.Warn("webdb scan failed", "task_id", task.ID, "kind", task.Kind,
			"target", task.Target, "error", errText)
	}
	data, _ := json.Marshal(summary)
	if err := w.store.CompleteWebDBScanTask(ctx, task.ID, errText, data); err != nil {
		slog.Error("complete webdb scan task failed", "task_id", task.ID, "error", err)
	}
	detail, _ := json.Marshal(map[string]interface{}{
		"task_id":       task.ID,
		"kind":          task.Kind,
		"target":        task.Target,
		"db_type":       task.DBType,
		"credential_id": task.CredentialID,
		"status":        taskStatus,
		"error":         errText,
	})
	if err := w.store.AppendAuditLog(ctx, store.AuditLog{
		Actor:      "webdb-worker",
		Method:     "POST",
		Path:       "internal/webdb/scan",
		Status:     status,
		DurationMS: 0,
		Detail:     detail,
	}); err != nil {
		slog.Error("append webdb scan audit failed", "task_id", task.ID, "error", err)
	}
}

// webDBAssetsJSON maps detected products to matcher assets. Products without
// a version are recorded on the target row but cannot feed CVE matching.
func webDBAssetsJSON(kind, target string, products []webdbscan.Product) []byte {
	assets := make([]map[string]interface{}, 0, len(products))
	for _, p := range products {
		if p.Version == "" {
			continue
		}
		assets = append(assets, map[string]interface{}{
			"name":     p.Name,
			"version":  p.Version,
			"format":   kind,
			"vendor":   "",
			"location": target,
			"type":     "PACKAGE",
		})
	}
	data, _ := json.Marshal(map[string]interface{}{"assets": assets})
	return data
}
