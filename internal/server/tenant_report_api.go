package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"

	"vuln-scanner/internal/store"
)

func tenantIDParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "tenantId"), 10, 64)
}

func (s *RESTServer) getTenantReport(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDParam(r)
	if err != nil || tenantID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	report, err := s.store.GetTenantReport(r.Context(), tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "tenant report settings not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *RESTServer) updateTenantReport(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantIDParam(r)
	if err != nil || tenantID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	var in struct {
		Enabled  *bool    `json:"enabled"`
		Schedule string   `json:"schedule"`
		Timezone string   `json:"timezone"`
		To       []string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}

	current, err := s.store.GetTenantReport(r.Context(), tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "tenant report settings not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	next := current
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if strings.TrimSpace(in.Schedule) != "" {
		next.Schedule = strings.TrimSpace(in.Schedule)
	}
	if strings.TrimSpace(in.Timezone) != "" {
		next.Timezone = strings.TrimSpace(in.Timezone)
	}
	if in.To != nil {
		next.To = cleanRecipients(in.To)
	}
	if _, err := cron.ParseStandard(next.Schedule); err != nil {
		writeError(w, http.StatusBadRequest, "schedule must be a valid cron expression: "+err.Error())
		return
	}
	if _, err := time.LoadLocation(next.Timezone); err != nil {
		writeError(w, http.StatusBadRequest, "timezone is invalid: "+err.Error())
		return
	}
	updated, err := s.store.UpsertTenantReport(r.Context(), store.TenantReport{
		TenantID: next.TenantID,
		Enabled:  next.Enabled,
		Schedule: next.Schedule,
		Timezone: next.Timezone,
		To:       next.To,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *RESTServer) sendTenantReport(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil {
		writeError(w, http.StatusInternalServerError, "worker not available")
		return
	}
	tenantID, err := tenantIDParam(r)
	if err != nil || tenantID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	if _, err := s.store.GetTenantReport(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, "tenant report settings not found")
		return
	}
	sentAt, err := s.worker.SendReportNow(r.Context(), &tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "sent",
		"tenant_id":    tenantID,
		"generated_at": sentAt,
	})
}

func cleanRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, addr := range in {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		out = append(out, addr)
	}
	return out
}
