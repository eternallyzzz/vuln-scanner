package server

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/cloudscan"
	"vuln-scanner/internal/store"
)

type cloudAccountInput struct {
	Provider               string   `json:"provider"`
	Name                   string   `json:"name"`
	AccountID              string   `json:"account_id"`
	Regions                []string `json:"regions"`
	RefreshIntervalMinutes int      `json:"refresh_interval_minutes"`
	Enabled                *bool    `json:"enabled"`

	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	TenantID        string `json:"tenant_id"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	ProjectID       string `json:"project_id"`
	ClientEmail     string `json:"client_email"`
	PrivateKey      string `json:"private_key"`
}

func (s *RESTServer) listCloudAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.ListCloudAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]interface{}, 0, len(accounts))
	for i := range accounts {
		out = append(out, cloudAccountView(&accounts[i]))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"accounts": out})
}

func (s *RESTServer) createCloudAccount(w http.ResponseWriter, r *http.Request) {
	var in cloudAccountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if s.cloudCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "cloud scan is disabled or the master key is not configured")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	name := strings.TrimSpace(in.Name)
	accountID := strings.TrimSpace(in.AccountID)
	if provider != "aws" && provider != "azure" && provider != "gcp" {
		writeError(w, http.StatusBadRequest, "provider must be aws, azure or gcp")
		return
	}
	if name == "" || accountID == "" {
		writeError(w, http.StatusBadRequest, "name and account_id are required")
		return
	}
	cred := cloudscan.Credentials{Provider: provider}
	switch provider {
	case "aws":
		cred.AccessKeyID = strings.TrimSpace(in.AccessKeyID)
		cred.SecretAccessKey = strings.TrimSpace(in.SecretAccessKey)
		cred.SessionToken = strings.TrimSpace(in.SessionToken)
	case "azure":
		cred.TenantID = strings.TrimSpace(in.TenantID)
		cred.ClientID = strings.TrimSpace(in.ClientID)
		cred.ClientSecret = strings.TrimSpace(in.ClientSecret)
		cred.SubscriptionID = accountID
	case "gcp":
		cred.ProjectID = accountID
		cred.ClientEmail = strings.TrimSpace(in.ClientEmail)
		cred.PrivateKey = strings.TrimSpace(in.PrivateKey)
	}
	if _, err := cloudscan.NewClient(cred, in.Regions, s.cfg.CloudScan.Timeout()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plain, _ := json.Marshal(cred)
	ciphertext, err := s.cloudCipher.Encrypt(plain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	refresh := in.RefreshIntervalMinutes
	if refresh <= 0 {
		refresh = s.cfg.CloudScan.DefaultRefreshIntervalMinutes
	}
	account, err := s.store.CreateCloudAccount(r.Context(), provider, name, accountID,
		dedupTags(in.Regions), ciphertext, refresh, actorFromRequest(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"account": cloudAccountView(account)})
}

func (s *RESTServer) updateCloudAccount(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "accountId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid account id")
		return
	}
	existing, err := s.store.GetCloudAccount(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.cloudCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "cloud scan is disabled or the master key is not configured")
		return
	}
	var in cloudAccountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	plain, err := s.cloudCipher.Decrypt(existing.CredentialCiphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential corrupted: "+err.Error())
		return
	}
	var cred cloudscan.Credentials
	_ = json.Unmarshal(plain, &cred)
	applyCloudCredentialOverrides(&cred, &in)
	if _, err := cloudscan.NewClient(cred, existing.Regions, s.cfg.CloudScan.Timeout()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	newPlain, _ := json.Marshal(cred)
	ciphertext, err := s.cloudCipher.Encrypt(newPlain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = existing.Name
	}
	regions := in.Regions
	if regions == nil {
		regions = existing.Regions
	}
	refresh := in.RefreshIntervalMinutes
	if refresh <= 0 {
		refresh = existing.RefreshIntervalMinutes
	}
	enabled := existing.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	account, err := s.store.UpdateCloudAccount(r.Context(), id, name, regions, refresh, enabled, ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"account": cloudAccountView(account)})
}

func (s *RESTServer) deleteCloudAccount(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "accountId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid account id")
		return
	}
	if _, err := s.store.GetCloudAccount(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.DisableCloudAccount(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *RESTServer) refreshCloudAccount(w http.ResponseWriter, r *http.Request) {
	if s.cloudCipher == nil || s.worker == nil {
		writeError(w, http.StatusServiceUnavailable, "cloud scan is disabled")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "accountId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid account id")
		return
	}
	account, err := s.store.GetCloudAccount(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !account.Enabled {
		writeError(w, http.StatusBadRequest, "account is disabled")
		return
	}
	s.worker.TriggerCloudRefresh(id)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"account_id": id, "status": "queued"})
}

func (s *RESTServer) listCloudResources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	accountID, _ := strconv.ParseInt(q.Get("account_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	resources, total, err := s.store.ListCloudResources(r.Context(), store.CloudResourceFilter{
		Provider:     q.Get("provider"),
		AccountID:    accountID,
		ResourceType: q.Get("resource_type"),
		Region:       q.Get("region"),
		Status:       q.Get("status"),
		Q:            q.Get("q"),
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"resources": resources, "total": total})
}

func (s *RESTServer) exportCloudResourcesCSV(w http.ResponseWriter, r *http.Request) {
	resources, _, err := s.store.ListCloudResources(r.Context(), store.CloudResourceFilter{Limit: 10000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cloud-resources.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"provider", "resource_type", "resource_id", "name", "region", "status", "tags", "last_seen"})
	for _, r := range resources {
		tags, _ := json.Marshal(r.Tags)
		_ = cw.Write([]string{
			r.Provider, r.ResourceType, r.ResourceID, r.Name, r.Region, r.Status,
			string(tags), r.LastSeen.Format("2006-01-02 15:04:05"),
		})
	}
	cw.Flush()
}

func cloudAccountView(a *store.CloudAccount) map[string]interface{} {
	return map[string]interface{}{
		"id":                       a.ID,
		"provider":                 a.Provider,
		"name":                     a.Name,
		"account_id":               a.AccountID,
		"regions":                  a.Regions,
		"enabled":                  a.Enabled,
		"refresh_interval_minutes": a.RefreshIntervalMinutes,
		"last_refresh_at":          a.LastRefreshAt,
		"last_error":               a.LastError,
		"created_by":               a.CreatedBy,
		"created_at":               a.CreatedAt,
		"updated_at":               a.UpdatedAt,
	}
}

func applyCloudCredentialOverrides(cred *cloudscan.Credentials, in *cloudAccountInput) {
	switch cred.Provider {
	case "aws":
		if v := strings.TrimSpace(in.AccessKeyID); v != "" {
			cred.AccessKeyID = v
		}
		if v := strings.TrimSpace(in.SecretAccessKey); v != "" {
			cred.SecretAccessKey = v
		}
		if v := strings.TrimSpace(in.SessionToken); v != "" {
			cred.SessionToken = v
		}
	case "azure":
		if v := strings.TrimSpace(in.TenantID); v != "" {
			cred.TenantID = v
		}
		if v := strings.TrimSpace(in.ClientID); v != "" {
			cred.ClientID = v
		}
		if v := strings.TrimSpace(in.ClientSecret); v != "" {
			cred.ClientSecret = v
		}
	case "gcp":
		if v := strings.TrimSpace(in.ClientEmail); v != "" {
			cred.ClientEmail = v
		}
		if v := strings.TrimSpace(in.PrivateKey); v != "" {
			cred.PrivateKey = v
		}
	}
}
