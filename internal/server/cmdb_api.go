package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

func (s *RESTServer) listAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	assets, total, err := s.store.ListAssets(r.Context(), store.AssetFilters{
		AssetType:    q.Get("asset_type"),
		Environment:  q.Get("environment"),
		BusinessUnit: q.Get("business_unit"),
		Owner:        q.Get("owner"),
		Lifecycle:    q.Get("lifecycle"),
		AgentID:      q.Get("agent_id"),
		Tag:          q.Get("tag"),
		Q:            q.Get("q"),
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"assets": assets, "total": total})
}

func (s *RESTServer) getAsset(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "assetId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid asset id")
		return
	}
	asset, err := s.store.GetAsset(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "asset not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, asset)
}

type updateAssetInput struct {
	Environment  string   `json:"environment"`
	BusinessUnit string   `json:"business_unit"`
	Owner        string   `json:"owner"`
	Lifecycle    string   `json:"lifecycle"`
	Tags         []string `json:"tags"`
}

func (s *RESTServer) updateAsset(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "assetId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid asset id")
		return
	}
	var in updateAssetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	for _, v := range []struct {
		name, val string
	}{
		{"environment", in.Environment},
		{"business_unit", in.BusinessUnit},
		{"owner", in.Owner},
	} {
		if len(v.val) > 100 {
			writeError(w, 400, v.name+" too long (max 100)")
			return
		}
	}
	if in.Lifecycle != "" && in.Lifecycle != "active" && in.Lifecycle != "retired" {
		writeError(w, 400, "lifecycle must be active or retired")
		return
	}
	actor := strings.TrimSpace(r.Header.Get("X-User"))
	if actor == "" {
		actor = "api"
	}
	asset, err := s.store.UpdateAssetMeta(r.Context(), id, in.Environment,
		in.BusinessUnit, in.Owner, in.Lifecycle, in.Tags, actor)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "asset not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, asset)
}

func (s *RESTServer) getAssetChanges(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "assetId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid asset id")
		return
	}
	asset, err := s.store.GetAsset(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "asset not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	changes, err := s.store.ListAssetChanges(r.Context(), asset.AssetKey, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"changes": changes})
}

func (s *RESTServer) getAssetRelations(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "assetId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid asset id")
		return
	}
	asset, err := s.store.GetAsset(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "asset not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	relations, err := s.store.ListAssetRelations(r.Context(), asset.AssetKey)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"relations": relations})
}

func (s *RESTServer) assetSummary(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.AssetSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"summary": rows})
}
