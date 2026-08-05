package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/report"
)

const reportSendTimeout = 2 * time.Minute

// reportLoop starts the single cron-driven panorama report job. It is a
// no-op when reporting is not enabled or the shared SMTP settings are absent.
func (w *Worker) reportLoop(ctx context.Context) {
	if w.reportCfg == nil || !w.reportCfg.Enabled {
		return
	}
	if w.reportSMTP == nil || w.reportSMTP.Host == "" {
		slog.Warn("reporting enabled but alerting.smtp is not configured")
		return
	}
	loc, err := w.reportCfg.Location()
	if err != nil {
		slog.Error("reporting timezone invalid", "error", err)
		return
	}
	c := cron.New(cron.WithLocation(loc))
	if _, err := c.AddFunc(w.reportCfg.ScheduleSpec(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), reportSendTimeout)
		defer cancel()
		if _, err := w.SendReportNow(ctx); err != nil {
			slog.Error("scheduled report failed", "error", err)
		}
	}); err != nil {
		slog.Error("reporting schedule invalid", "error", err)
		return
	}
	c.Start()
	defer c.Stop()
	slog.Info("reporting schedule started",
		"schedule", w.reportCfg.ScheduleSpec(),
		"timezone", w.reportCfg.Timezone,
		"recipients", len(w.reportCfg.To))
	select {
	case <-ctx.Done():
		return
	case <-w.done:
		return
	}
}

// SendReportNow builds and sends the panorama report immediately. Concurrent
// invocations (scheduled + manual) are serialized and the second one fails
// fast instead of stacking up.
func (w *Worker) SendReportNow(ctx context.Context) (time.Time, error) {
	if w.reportCfg == nil || !w.reportCfg.Enabled {
		return time.Time{}, errors.New("reporting is not enabled")
	}
	if w.reportSMTP == nil || w.reportSMTP.Host == "" {
		return time.Time{}, errors.New("reporting SMTP is not configured")
	}
	if w.store == nil {
		return time.Time{}, errors.New("report store unavailable")
	}

	w.reportMu.Lock()
	if w.reportRunning {
		w.reportMu.Unlock()
		return time.Time{}, errors.New("report is already running")
	}
	w.reportRunning = true
	w.reportMu.Unlock()
	defer func() {
		w.reportMu.Lock()
		w.reportRunning = false
		w.reportMu.Unlock()
	}()

	data, err := report.Build(ctx, w.store)
	if err != nil {
		return time.Time{}, err
	}
	htmlBody, err := report.RenderHTML(*data)
	if err != nil {
		return time.Time{}, err
	}
	csvData, err := report.BuildCSV(*data)
	if err != nil {
		return time.Time{}, err
	}
	subject := fmt.Sprintf("[VulnScanner] Daily Security Report %s", data.Period)
	notifier := alert.NewSMTPNotifier(w.reportSMTP)
	attachments := []alert.Attachment{{
		Name:        "vulnscanner-report-" + data.Period + ".csv",
		ContentType: "text/csv; charset=UTF-8",
		Data:        csvData,
	}}
	if err := notifier.SendMail(ctx, subject, htmlBody, w.reportCfg.To, attachments); err != nil {
		return time.Time{}, err
	}
	slog.Info("report sent", "period", data.Period, "recipients", len(w.reportCfg.To))
	return data.GeneratedAt, nil
}
