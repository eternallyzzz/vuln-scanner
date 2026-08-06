package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

var (
	errInvalidTenant   = errors.New("invalid or unknown X-Tenant-ID")
	errTenantForbidden = errors.New("forbidden: resource belongs to another tenant")
)

type apiKeyTenantCtxKeyType int

const apiKeyTenantCtxKey apiKeyTenantCtxKeyType = iota + 1

// apiKeyTenantFromContext returns the tenant bound to a DB-backed API key,
// or 0 when the key is global.
func apiKeyTenantFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(apiKeyTenantCtxKey).(int64)
	return id
}

// scope resolves the effective tenant scope of a request:
//   - admin user: global unless X-Tenant-ID is supplied
//   - operator/viewer: their own tenant
//   - API key without X-Tenant-ID: global (legacy behavior)
//   - tenant-bound API key: that tenant; X-Tenant-ID must match
//   - API key with X-Tenant-ID: that tenant, validated against the tenants table
func (s *RESTServer) scope(r *http.Request) (int64, bool, error) {
	if u := userFromContext(r.Context()); u != nil {
		if u.Role == "admin" {
			header := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
			if header == "" {
				return 0, false, nil
			}
			id, err := s.validatedTenantID(r, header)
			if err != nil {
				return 0, false, err
			}
			return id, true, nil
		}
		return u.TenantID, true, nil
	}
	header := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if bound := apiKeyTenantFromContext(r.Context()); bound > 0 {
		if header != "" {
			id, err := strconv.ParseInt(header, 10, 64)
			if err != nil || id != bound {
				return 0, false, errTenantForbidden
			}
		}
		return bound, true, nil
	}
	if header == "" {
		return 0, false, nil
	}
	id, err := s.validatedTenantID(r, header)
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (s *RESTServer) validatedTenantID(r *http.Request, header string) (int64, error) {
	if s.store == nil {
		return 0, errInvalidTenant
	}
	id, err := strconv.ParseInt(header, 10, 64)
	if err != nil || id <= 0 {
		return 0, errInvalidTenant
	}
	exists, err := s.store.TenantExists(r.Context(), id)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, errInvalidTenant
	}
	return id, nil
}

// tid returns the tenant filter to pass to store list methods (nil = all).
func (s *RESTServer) tid(r *http.Request) (*int64, error) {
	id, restrict, err := s.scope(r)
	if err != nil {
		return nil, err
	}
	if !restrict {
		return nil, nil
	}
	return &id, nil
}

// requireAgent rejects access to an agent that does not belong to the
// caller's tenant (admin and global API-key calls always pass).
func (s *RESTServer) requireAgent(r *http.Request, agentID string) error {
	id, restrict, err := s.scope(r)
	if err != nil {
		return err
	}
	if !restrict {
		return nil
	}
	agent, err := s.store.GetAgent(r.Context(), agentID)
	if err != nil {
		return err
	}
	if agent.TenantID != id {
		return errTenantForbidden
	}
	return nil
}

func (s *RESTServer) requireCampaign(r *http.Request, campaignID int64) error {
	id, restrict, err := s.scope(r)
	if err != nil {
		return err
	}
	if !restrict {
		return nil
	}
	c, err := s.store.GetPatchCampaign(r.Context(), campaignID)
	if err != nil {
		return err
	}
	if c.TenantID != id {
		return errTenantForbidden
	}
	return nil
}

func (s *RESTServer) requireAsset(r *http.Request, assetID int64) error {
	id, restrict, err := s.scope(r)
	if err != nil {
		return err
	}
	if !restrict {
		return nil
	}
	asset, err := s.store.GetAsset(r.Context(), assetID)
	if err != nil {
		return err
	}
	if asset.AgentID == "" {
		return nil
	}
	agent, err := s.store.GetAgent(r.Context(), asset.AgentID)
	if err != nil {
		return err
	}
	if agent.TenantID != id {
		return errTenantForbidden
	}
	return nil
}

func (s *RESTServer) requireAssetKey(r *http.Request, assetKey string) error {
	id, restrict, err := s.scope(r)
	if err != nil {
		return err
	}
	if !restrict {
		return nil
	}
	asset, err := s.store.GetAssetByKey(r.Context(), assetKey)
	if err != nil {
		return err
	}
	if asset.AgentID == "" {
		return nil
	}
	agent, err := s.store.GetAgent(r.Context(), asset.AgentID)
	if err != nil {
		return err
	}
	if agent.TenantID != id {
		return errTenantForbidden
	}
	return nil
}

func (s *RESTServer) requireException(r *http.Request, exceptionID int64) error {
	id, restrict, err := s.scope(r)
	if err != nil {
		return err
	}
	if !restrict {
		return nil
	}
	ex, err := s.store.GetException(r.Context(), exceptionID)
	if err != nil {
		return err
	}
	if ex.AssetKey == "" {
		return nil
	}
	asset, err := s.store.GetAssetByKey(r.Context(), ex.AssetKey)
	if err != nil {
		return errTenantForbidden
	}
	agent, err := s.store.GetAgent(r.Context(), asset.AgentID)
	if err != nil {
		return err
	}
	if agent.TenantID != id {
		return errTenantForbidden
	}
	return nil
}

func (s *RESTServer) requirePatchTask(r *http.Request, taskID int64) error {
	task, err := s.store.GetPatchTask(r.Context(), taskID)
	if err != nil {
		return err
	}
	return s.requireAgent(r, task.AgentID)
}

func (s *RESTServer) requireAlert(r *http.Request, alertID int64) error {
	detail, err := s.store.GetAlertDetail(r.Context(), alertID)
	if err != nil {
		return err
	}
	return s.requireAgent(r, detail.AgentID)
}

func (s *RESTServer) requireEDRFinding(r *http.Request, findingID int64) error {
	finding, err := s.store.GetEDRFinding(r.Context(), findingID)
	if err != nil {
		return err
	}
	return s.requireAgent(r, finding.AgentID)
}

// writeScopeError maps tenant-scope failures to HTTP status codes.
func writeScopeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidTenant):
		writeError(w, 400, err.Error())
	case errors.Is(err, errTenantForbidden):
		writeError(w, 403, err.Error())
	case errors.Is(err, pgx.ErrNoRows):
		writeError(w, 404, "not found")
	default:
		writeError(w, 500, err.Error())
	}
}

func (s *RESTServer) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.ListTenants(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"tenants": tenants})
}

func (s *RESTServer) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(strings.ToLower(in.Slug))
	if in.Name == "" || in.Slug == "" {
		writeError(w, 400, "name and slug are required")
		return
	}
	tenant, err := s.store.CreateTenant(r.Context(), in.Name, in.Slug)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, tenant)
}

func (s *RESTServer) setUserTenant(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil || userID <= 0 {
		writeError(w, 400, "invalid user id")
		return
	}
	var in struct {
		TenantID int64 `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if in.TenantID <= 0 {
		writeError(w, 400, "tenant_id is required")
		return
	}
	if _, err := s.store.GetTenantByID(r.Context(), in.TenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "tenant not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.store.SetUserTenant(r.Context(), userID, in.TenantID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"user_id": userID, "tenant_id": in.TenantID})
}

func (s *RESTServer) setAgentTenant(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, 400, "invalid agent id")
		return
	}
	var in struct {
		TenantID int64 `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if in.TenantID <= 0 {
		writeError(w, 400, "tenant_id is required")
		return
	}
	if _, err := s.store.GetTenantByID(r.Context(), in.TenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "tenant not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if _, err := s.store.GetAgent(r.Context(), agentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "agent not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.store.SetAgentTenant(r.Context(), agentID, in.TenantID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"agent_id": agentID, "tenant_id": in.TenantID})
}

// effectiveTenant resolves the tenant to use when creating agents/users:
// tenant-bound users always use their own; admin/global API key uses the
// requested tenant_id (default 1) or the X-Tenant-ID header when present.
func (s *RESTServer) effectiveTenant(r *http.Request, requested int64) (int64, error) {
	if u := userFromContext(r.Context()); u != nil && u.Role != "admin" {
		return u.TenantID, nil
	}
	id, restrict, err := s.scope(r)
	if err != nil {
		return 0, err
	}
	if restrict {
		return id, nil
	}
	if s.store == nil {
		return 0, errInvalidTenant
	}
	if requested > 0 {
		if exists, err := s.store.TenantExists(r.Context(), requested); err != nil {
			return 0, err
		} else if !exists {
			return 0, errInvalidTenant
		}
		return requested, nil
	}
	return 1, nil
}
