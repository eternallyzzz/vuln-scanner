package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

const (
	maxBulkMetaItems = 500
	maxTaskListItems = 200
)

type campaignGenerateInput struct {
	Name                 string   `json:"name"`
	AgentIDs             []string `json:"agent_ids"`
	Tags                 []string `json:"tags"`
	Environments         []string `json:"environments"`
	AssetNames           []string `json:"asset_names"`
	CVEIDs               []string `json:"cve_ids"`
	MinSeverity          string   `json:"min_severity"`
	MinCVSS              float64  `json:"min_cvss"`
	ApprovalRequired     *bool    `json:"approval_required"`
	WindowStart          string   `json:"window_start"`
	WindowEnd            string   `json:"window_end"`
	DryRun               bool     `json:"dry_run"`
	FollowUpSourceTaskID int64    `json:"-"`
}

func normalizeSeverity(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func severityRank(s string) int {
	switch normalizeSeverity(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func strSliceContains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func matchesAssetFilters(assetName string, meta store.AssetMeta, tags, environments, assetNames []string) bool {
	if len(assetNames) > 0 && !strSliceContains(assetNames, assetName) {
		return false
	}
	if len(environments) > 0 && !strSliceContains(environments, meta.Environment) {
		return false
	}
	if len(tags) > 0 {
		matched := false
		for _, want := range tags {
			if strSliceContains(meta.Tags, want) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// validateCampaignInput normalizes the selection fields and rejects invalid
// severity, CVSS or window values. Window strings are validated but left in
// place; they are parsed again by the caller.
func validateCampaignInput(in *campaignGenerateInput) error {
	in.MinSeverity = normalizeSeverity(in.MinSeverity)
	if in.MinSeverity != "" && severityRank(in.MinSeverity) == 0 {
		return fmt.Errorf("min_severity must be LOW, MEDIUM, HIGH or CRITICAL")
	}
	if in.MinCVSS < 0 || in.MinCVSS > 10 {
		return fmt.Errorf("min_cvss must be between 0 and 10")
	}
	clean := func(list []string) []string {
		var out []string
		for _, v := range list {
			v = strings.TrimSpace(v)
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	in.AgentIDs = clean(in.AgentIDs)
	in.Tags = clean(in.Tags)
	in.Environments = clean(in.Environments)
	in.AssetNames = clean(in.AssetNames)
	for i, c := range in.CVEIDs {
		in.CVEIDs[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	cveIDs := in.CVEIDs[:0]
	for _, c := range in.CVEIDs {
		if c != "" {
			cveIDs = append(cveIDs, c)
		}
	}
	in.CVEIDs = cveIDs

	if len(in.AgentIDs) == 0 && len(in.Tags) == 0 &&
		len(in.Environments) == 0 && len(in.AssetNames) == 0 {
		return fmt.Errorf("at least one of agent_ids, tags, environments, asset_names is required")
	}
	if len(in.AgentIDs) > maxCampaignAgents {
		return fmt.Errorf("agent_ids exceeds %d entries", maxCampaignAgents)
	}
	if in.WindowStart != "" {
		if _, err := time.Parse(time.RFC3339, in.WindowStart); err != nil {
			return fmt.Errorf("window_start must be RFC3339")
		}
	}
	if in.WindowEnd != "" {
		if _, err := time.Parse(time.RFC3339, in.WindowEnd); err != nil {
			return fmt.Errorf("window_end must be RFC3339")
		}
	}
	if in.WindowStart != "" && in.WindowEnd != "" {
		start, _ := time.Parse(time.RFC3339, in.WindowStart)
		end, _ := time.Parse(time.RFC3339, in.WindowEnd)
		if !end.After(start) {
			return fmt.Errorf("window_end must be after window_start")
		}
	}
	return nil
}

func parseCampaignWindow(start, end string) (*time.Time, *time.Time, error) {
	var windowStart, windowEnd *time.Time
	if start != "" {
		t, err := time.Parse(time.RFC3339, start)
		if err != nil {
			return nil, nil, fmt.Errorf("window_start must be RFC3339")
		}
		windowStart = &t
	}
	if end != "" {
		t, err := time.Parse(time.RFC3339, end)
		if err != nil {
			return nil, nil, fmt.Errorf("window_end must be RFC3339")
		}
		windowEnd = &t
	}
	if windowStart != nil && windowEnd != nil && !windowEnd.After(*windowStart) {
		return nil, nil, fmt.Errorf("window_end must be after window_start")
	}
	return windowStart, windowEnd, nil
}

func requestActor(r *http.Request) string {
	actor := strings.TrimSpace(r.Header.Get("X-User"))
	if actor == "" {
		actor = "api"
	}
	return actor
}

func (s *RESTServer) generatePatchCampaign(w http.ResponseWriter, r *http.Request) {
	var in campaignGenerateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	tenantID := int64(1)
	if tid != nil {
		tenantID = *tid
	}
	res, err := runCampaignGeneration(r.Context(), s.store, s.cfg.Patch, in, requestActor(r), tenantID)
	if errors.Is(err, errPatchDisabled) || errors.Is(err, errTaskLimitExceeded) {
		writeError(w, 400, err.Error())
		return
	}
	if errors.Is(err, errNoAgentsMatch) {
		writeError(w, 404, err.Error())
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if res.DryRun {
		writeJSON(w, 200, map[string]interface{}{
			"dry_run": true, "matched": res.Matched, "counts": res.Counts,
			"errors": res.Errors,
		})
		return
	}
	writeJSON(w, 201, map[string]interface{}{
		"campaign": res.Campaign, "created": res.Created, "counts": res.Counts,
		"tasks": res.Tasks, "errors": res.Errors,
	})
}

func (s *RESTServer) listPatchCampaigns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	campaigns, total, err := s.store.ListPatchCampaigns(r.Context(), limit, offset, tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"campaigns": campaigns, "total": total})
}

func (s *RESTServer) getPatchCampaign(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "campaignId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid campaign id")
		return
	}
	campaign, err := s.store.GetPatchCampaign(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "campaign not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requireCampaign(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	summary, err := s.store.CampaignSummary(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	audit, err := s.store.GetCampaignAudit(r.Context(), id, 50)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"campaign": campaign, "summary": summary, "audit": audit,
	})
}

func (s *RESTServer) listPatchCampaignTasks(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "campaignId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid campaign id")
		return
	}
	if _, err := s.store.GetPatchCampaign(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "campaign not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requireCampaign(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > maxTaskListItems {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	tasks, err := s.store.ListCampaignTasks(r.Context(), id, q.Get("status"),
		q.Get("asset_name"), limit, offset)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"tasks": tasks, "total": len(tasks)})
}

func campaignStatusTransition(action string) (from []string, to string, ok bool) {
	switch action {
	case "approve":
		return []string{"pending"}, "approved", true
	case "reject":
		return []string{"pending"}, "rejected", true
	case "cancel":
		return []string{"pending", "approved"}, "cancelled", true
	case "retry":
		return []string{"failed", "cancelled"}, "pending", true
	default:
		return nil, "", false
	}
}

func (s *RESTServer) campaignSetStatus(w http.ResponseWriter, r *http.Request, action string) {
	id, err := strconv.ParseInt(chi.URLParam(r, "campaignId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid campaign id")
		return
	}
	if _, err := s.store.GetPatchCampaign(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "campaign not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requireCampaign(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	from, to, ok := campaignStatusTransition(action)
	if !ok {
		writeError(w, 400, "invalid campaign action")
		return
	}
	actor := requestActor(r)
	affected, err := s.store.BulkSetPatchTaskStatus(r.Context(), id, from, to, actor)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	detail, _ := json.Marshal(map[string]interface{}{"from": from, "to": to})
	if err := s.store.AppendCampaignAudit(r.Context(), id, action, actor, affected, detail); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	summary, err := s.store.CampaignSummary(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"campaign_id": id, "action": action, "affected": affected,
		"status_counts": summary.StatusCounts,
	})
}

func (s *RESTServer) campaignApprove(w http.ResponseWriter, r *http.Request) {
	s.campaignSetStatus(w, r, "approve")
}

func (s *RESTServer) campaignReject(w http.ResponseWriter, r *http.Request) {
	s.campaignSetStatus(w, r, "reject")
}

func (s *RESTServer) campaignCancel(w http.ResponseWriter, r *http.Request) {
	s.campaignSetStatus(w, r, "cancel")
}

func (s *RESTServer) campaignRetry(w http.ResponseWriter, r *http.Request) {
	s.campaignSetStatus(w, r, "retry")
}

func (s *RESTServer) listPatchTasksGlobal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > maxTaskListItems {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var campaignID int64
	if v := q.Get("campaign_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, 400, "campaign_id must be an integer")
			return
		}
		campaignID = id
	}
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	tasks, total, err := s.store.ListPatchTasksFiltered(r.Context(), q.Get("agent_id"),
		campaignID, q.Get("status"), q.Get("asset_name"), limit, offset, tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"tasks": tasks, "total": total})
}

type bulkMetaItem struct {
	AssetKey     string   `json:"asset_key"`
	Environment  string   `json:"environment"`
	BusinessUnit string   `json:"business_unit"`
	Owner        string   `json:"owner"`
	Lifecycle    string   `json:"lifecycle"`
	Tags         []string `json:"tags"`
}

func (s *RESTServer) bulkUpdateAssetMeta(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items []bulkMetaItem `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if len(in.Items) == 0 {
		writeError(w, 400, "items must not be empty")
		return
	}
	if len(in.Items) > maxBulkMetaItems {
		writeError(w, 400, fmt.Sprintf("items exceeds %d entries", maxBulkMetaItems))
		return
	}
	items := make([]store.AssetMetaUpdate, 0, len(in.Items))
	for _, it := range in.Items {
		if strings.TrimSpace(it.AssetKey) == "" {
			writeError(w, 400, "asset_key is required for every item")
			return
		}
		if err := s.requireAssetKey(r, strings.TrimSpace(it.AssetKey)); err != nil {
			writeScopeError(w, err)
			return
		}
		for _, field := range []struct{ name, val string }{
			{"environment", it.Environment}, {"business_unit", it.BusinessUnit},
			{"owner", it.Owner},
		} {
			if len(field.val) > 100 {
				writeError(w, 400, field.name+" too long (max 100)")
				return
			}
		}
		if it.Lifecycle != "" && it.Lifecycle != "active" && it.Lifecycle != "retired" {
			writeError(w, 400, "lifecycle must be active or retired")
			return
		}
		if len(it.Tags) > 50 {
			writeError(w, 400, "tags exceeds 50 entries per asset")
			return
		}
		for _, t := range it.Tags {
			if len(t) > 64 {
				writeError(w, 400, "tag too long (max 64)")
				return
			}
		}
		var tags []string
		if it.Tags != nil {
			tags = it.Tags
		}
		items = append(items, store.AssetMetaUpdate{
			AssetKey: strings.TrimSpace(it.AssetKey), Environment: it.Environment,
			BusinessUnit: it.BusinessUnit, Owner: it.Owner, Lifecycle: it.Lifecycle,
			Tags: tags,
		})
	}
	updated, err := s.store.BulkUpdateAssetMeta(r.Context(), items, requestActor(r))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"updated": updated, "total_items": len(items)})
}
