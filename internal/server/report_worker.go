package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/robfig/cron/v3"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/report"
	"vuln-scanner/internal/store"
)

const (
	reportSendTimeout       = 2 * time.Minute
	reportReconcileInterval = 60 * time.Second
)

type reportSchedule struct {
	settings store.TenantReport
	cron     *cron.Cron
}

// reportLoop keeps tenant report crons in sync with tenant_reports. Instead
// of registering schedules once at startup, it reconciles every 60 seconds
// so PUT /api/v1/tenants/{id}/report changes take effect without a restart.
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
	schedules := map[int64]*reportSchedule{}
	defer w.stopReportSchedules(schedules)
	w.reconcileReportSchedules(ctx, schedules)
	if len(schedules) == 0 {
		slog.Info("reporting schedule started with no enabled tenant deliveries")
	}
	ticker := time.NewTicker(reportReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.reconcileReportSchedules(ctx, schedules)
		}
	}
}

// reconcileReportSchedules diffs the live cron map against the database and
// stops/starts only the schedules that actually changed. Query failures keep
// existing crons untouched and are retried on the next tick.
func (w *Worker) reconcileReportSchedules(ctx context.Context, schedules map[int64]*reportSchedule) {
	if w.store == nil {
		return
	}
	reports, err := w.store.ListTenantReports(ctx)
	if err != nil {
		slog.Error("reporting tenant settings lookup failed", "error", err)
		return
	}
	current := make(map[int64]store.TenantReport, len(schedules))
	for id, sched := range schedules {
		current[id] = sched.settings
	}
	add, update, remove := reportReconcilePlan(current, reports)
	for _, id := range remove {
		if sched := schedules[id]; sched != nil {
			sched.cron.Stop()
			delete(schedules, id)
			slog.Info("reporting tenant schedule removed",
				"tenant_id", id)
		}
	}
	for _, tr := range add {
		w.startReportSchedule(ctx, tr, schedules)
	}
	for _, tr := range update {
		w.updateReportSchedule(ctx, tr, schedules)
	}
}

func (w *Worker) startReportSchedule(ctx context.Context, tr store.TenantReport, schedules map[int64]*reportSchedule) {
	loc, err := time.LoadLocation(tr.Timezone)
	if err != nil {
		slog.Error("reporting tenant timezone invalid", "tenant_id", tr.TenantID, "error", err)
		return
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
		return
	}
	c.Start()
	schedules[tr.TenantID] = &reportSchedule{settings: tr, cron: c}
	slog.Info("reporting tenant schedule started",
		"tenant_id", tr.TenantID,
		"schedule", tr.Schedule,
		"timezone", tr.Timezone,
		"recipients", len(tr.To))
}

func (w *Worker) updateReportSchedule(ctx context.Context, tr store.TenantReport, schedules map[int64]*reportSchedule) {
	existing, ok := schedules[tr.TenantID]
	if !ok {
		w.startReportSchedule(ctx, tr, schedules)
		return
	}
	// Validate the new settings before stopping the old cron; a transiently
	// invalid row (for example imported externally) should not take down an
	// otherwise healthy schedule.
	if _, err := time.LoadLocation(tr.Timezone); err != nil {
		slog.Error("reporting tenant timezone invalid", "tenant_id", tr.TenantID, "error", err)
		return
	}
	if _, err := cron.ParseStandard(tr.Schedule); err != nil {
		slog.Error("reporting tenant schedule invalid", "tenant_id", tr.TenantID, "error", err)
		return
	}
	existing.cron.Stop()
	delete(schedules, tr.TenantID)
	w.startReportSchedule(ctx, tr, schedules)
}

func (w *Worker) stopReportSchedules(schedules map[int64]*reportSchedule) {
	for id, sched := range schedules {
		sched.cron.Stop()
		delete(schedules, id)
	}
}

// reportReconcilePlan is the pure diff used by the report scheduler. It
// returns crons to add, crons whose settings changed and must be replaced,
// and tenant ids whose cron must be removed (deleted, disabled, or with no
// recipients).
func reportReconcilePlan(current map[int64]store.TenantReport, reports []store.TenantReport) (add, update []store.TenantReport, remove []int64) {
	desired := make(map[int64]store.TenantReport, len(reports))
	for _, tr := range reports {
		desired[tr.TenantID] = tr
	}
	for id := range current {
		tr, ok := desired[id]
		if !ok || !tr.Enabled || len(tr.To) == 0 {
			remove = append(remove, id)
		}
	}
	for _, tr := range reports {
		if !tr.Enabled || len(tr.To) == 0 {
			continue
		}
		cur, ok := current[tr.TenantID]
		if !ok {
			add = append(add, tr)
			continue
		}
		if !reportSettingsEqual(cur, tr) {
			update = append(update, tr)
		}
	}
	sort.Slice(add, func(i, j int) bool { return add[i].TenantID < add[j].TenantID })
	sort.Slice(update, func(i, j int) bool { return update[i].TenantID < update[j].TenantID })
	sort.Slice(remove, func(i, j int) bool { return remove[i] < remove[j] })
	return add, update, remove
}

// reportSettingsEqual compares the fields that drive scheduling: enabled,
// cron expression, timezone, and the recipient collection.
func reportSettingsEqual(a, b store.TenantReport) bool {
	return a.Enabled == b.Enabled &&
		a.Schedule == b.Schedule &&
		a.Timezone == b.Timezone &&
		sameRecipientSet(a.To, b.To)
}

func sameRecipientSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, addr := range a {
		counts[addr]++
	}
	for _, addr := range b {
		counts[addr]--
		if counts[addr] < 0 {
			return false
		}
	}
	return true
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
