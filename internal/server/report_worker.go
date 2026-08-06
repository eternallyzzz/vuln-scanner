package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/robfig/cron/v3"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/report"
)

const reportSendTimeout = 2 * time.Minute

// reportLoop starts one cron-driven panorama report job per enabled tenant.
// It is a no-op when reporting is not enabled or the shared SMTP settings
// are absent.
func (w *Worker) reportLoop(ctx context.Context) {
	if w.reportCfg == nil || !w.reportCfg.Enabled {
		return
	}
	if w.reportSMTP == nil || w.reportSMTP.Host == "" {
		slog.Warn("reporting enabled but alerting.smtp is not configured")
		return
	}
	reports, err := w.store.ListEnabledTenantReports(ctx)
	if err != nil {
		slog.Error("reporting tenant settings lookup failed", "error", err)
		return
	}
	var crons []*cron.Cron
	for _, tr := range reports {
		if len(tr.To) == 0 {
			slog.Warn("reporting tenant has no recipients; skipping schedule",
				"tenant_id", tr.TenantID)
			continue
		}
		loc, err := time.LoadLocation(tr.Timezone)
		if err != nil {
			slog.Error("reporting tenant timezone invalid", "tenant_id", tr.TenantID, "error", err)
			continue
		}
		c := cron.New(cron.WithLocation(loc))
		tenantID := tr.TenantID
		if _, err := c.AddFunc(tr.Schedule, func() {
			ctx, cancel := context.WithTimeout(context.Background(), reportSendTimeout)
			defer cancel()
			if _, err := w.SendReportNow(ctx, &tenantID); err != nil {
				slog.Error("scheduled tenant report failed", "tenant_id", tenantID, "error", err)
			}
		}); err != nil {
			slog.Error("reporting tenant schedule invalid", "tenant_id", tr.TenantID, "error", err)
			continue
		}
		c.Start()
		crons = append(crons, c)
		slog.Info("reporting tenant schedule started",
			"tenant_id", tr.TenantID,
			"schedule", tr.Schedule,
			"timezone", tr.Timezone,
			"recipients", len(tr.To))
	}
	if len(crons) == 0 {
		slog.Info("reporting schedule started with no enabled tenant deliveries")
	}
	defer func() {
		for _, c := range crons {
			c.Stop()
		}
	}()
	select {
	case <-ctx.Done():
		return
	case <-w.done:
		return
	}
}

// SendReportNow builds and sends the panorama report immediately for one
// tenant (nil = full panorama). Concurrent invocations per tenant are
// serialized through job_queue and the second one fails fast.
func (w *Worker) SendReportNow(ctx context.Context, tenantID *int64) (time.Time, error) {
	if w.reportCfg == nil || !w.reportCfg.Enabled {
		return time.Time{}, errors.New("reporting is not enabled")
	}
	if w.reportSMTP == nil || w.reportSMTP.Host == "" {
		return time.Time{}, errors.New("reporting SMTP is not configured")
	}
	if w.store == nil {
		return time.Time{}, errors.New("report store unavailable")
	}
	jobKey := ""
	if tenantID != nil {
		jobKey = strconv.FormatInt(*tenantID, 10)
	}
	jobID, inserted, err := w.store.EnqueueJob(ctx, "report_now", jobKey, nil)
	if err != nil {
		return time.Time{}, err
	}
	if !inserted {
		return time.Time{}, errors.New("report is already running")
	}

	w.reportMu.Lock()
	if w.reportRunning {
		w.reportMu.Unlock()
		_ = w.store.FinishJob(ctx, jobID, "report already running locally")
		return time.Time{}, errors.New("report is already running")
	}
	w.reportRunning = true
	w.reportMu.Unlock()
	defer func() {
		w.reportMu.Lock()
		w.reportRunning = false
		w.reportMu.Unlock()
	}()

	recipients := w.reportCfg.To
	if tenantID != nil {
		tr, err := w.store.GetTenantReport(ctx, *tenantID)
		if err != nil {
			_ = w.store.FinishJob(ctx, jobID, err.Error())
			return time.Time{}, err
		}
		if len(tr.To) == 0 {
			errText := "tenant report has no recipients"
			_ = w.store.FinishJob(ctx, jobID, errText)
			return time.Time{}, errors.New(errText)
		}
		recipients = tr.To
	}

	data, err := report.Build(ctx, w.store, tenantID)
	if err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return time.Time{}, err
	}
	htmlBody, err := report.RenderHTML(*data)
	if err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return time.Time{}, err
	}
	csvData, err := report.BuildCSV(*data)
	if err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return time.Time{}, err
	}
	subject := fmt.Sprintf("[VulnScanner] Daily Security Report %s", data.Period)
	if tenantID != nil {
		subject = fmt.Sprintf("[VulnScanner] Tenant %d Daily Security Report %s", *tenantID, data.Period)
	}
	notifier := alert.NewSMTPNotifier(w.reportSMTP)
	attachments := []alert.Attachment{{
		Name:        "vulnscanner-report-" + data.Period + ".csv",
		ContentType: "text/csv; charset=UTF-8",
		Data:        csvData,
	}}
	if err := notifier.SendMail(ctx, subject, htmlBody, recipients, attachments); err != nil {
		_ = w.store.FinishJob(ctx, jobID, err.Error())
		return time.Time{}, err
	}
	slog.Info("report sent", "period", data.Period, "recipients", len(recipients),
		"tenant_id", tenantID)
	return data.GeneratedAt, w.store.FinishJob(ctx, jobID, "")
}
