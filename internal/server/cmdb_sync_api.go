package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

const maxExternalImportRows = 5000

// reconcileAgentCMDB replays the latest stored snapshot of one agent through
// the FULL CMDB sync (backfills assets uploaded before CMDB existed).
func (s *RESTServer) reconcileAgentCMDB(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, 400, "agent_id required")
		return
	}
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}
	snap, err := s.store.GetAssetSnapshot(r.Context(), agentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, 404, "no snapshot for agent")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	counts, err := s.store.ReconcileAgentFromSnapshot(r.Context(), agentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id":    agentID,
		"snapshot_at": snap.CreatedAt,
		"mode":        snap.Mode,
		"upserted":    counts.Upserted,
		"retired":     counts.Retired,
		"relations":   counts.Relations,
		"changes":     counts.Changes,
	})
}

// reconcileAllCMDB replays the latest snapshot for every agent that has one.
func (s *RESTServer) reconcileAllCMDB(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), nil)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	results := make([]map[string]interface{}, 0, len(agents))
	var errorsList []string
	for _, ag := range agents {
		snap, err := s.store.GetAssetSnapshot(r.Context(), ag.ID)
		if err != nil {
			if err != pgx.ErrNoRows {
				errorsList = append(errorsList, ag.ID+": "+err.Error())
			}
			continue
		}
		counts, err := s.store.ReconcileAgentFromSnapshot(r.Context(), ag.ID)
		if err != nil {
			errorsList = append(errorsList, ag.ID+": "+err.Error())
			continue
		}
		results = append(results, map[string]interface{}{
			"agent_id":    ag.ID,
			"hostname":    ag.Hostname,
			"snapshot_at": snap.CreatedAt,
			"mode":        snap.Mode,
			"upserted":    counts.Upserted,
			"retired":     counts.Retired,
			"relations":   counts.Relations,
			"changes":     counts.Changes,
		})
	}
	writeJSON(w, 200, map[string]interface{}{
		"results": results,
		"errors":  errorsList,
	})
}

// exportAssets streams the asset ledger as JSON or CSV with the same filters
// as GET /assets, without the default 100-row page limit.
func (s *RESTServer) exportAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "json"
	}
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	filters := store.AssetFilters{
		AssetType:    q.Get("asset_type"),
		Environment:  q.Get("environment"),
		BusinessUnit: q.Get("business_unit"),
		Owner:        q.Get("owner"),
		Lifecycle:    q.Get("lifecycle"),
		AgentID:      q.Get("agent_id"),
		Tag:          q.Get("tag"),
		Q:            q.Get("q"),
		TenantID:     tid,
	}

	const pageSize = 5000
	const maxRows = 100000
	var assets []store.Asset
	for offset := 0; ; offset += pageSize {
		page, total, err := s.store.ListAssets(r.Context(), store.AssetFilters{
			AssetType:    filters.AssetType,
			Environment:  filters.Environment,
			BusinessUnit: filters.BusinessUnit,
			Owner:        filters.Owner,
			Lifecycle:    filters.Lifecycle,
			AgentID:      filters.AgentID,
			Tag:          filters.Tag,
			Q:            filters.Q,
			TenantID:     filters.TenantID,
			Limit:        pageSize,
			Offset:       offset,
		})
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		assets = append(assets, page...)
		if offset+len(page) >= total || len(page) == 0 || len(assets) >= maxRows {
			break
		}
	}

	switch format {
	case "csv":
		writeAssetCSV(w, assets)
	default:
		writeJSON(w, 200, map[string]interface{}{
			"assets":      assets,
			"exported_at": time.Now().UTC(),
		})
	}
}

func writeAssetCSV(w http.ResponseWriter, assets []store.Asset) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="assets.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{
		"asset_key", "asset_type", "name", "version", "format", "vendor", "arch",
		"location", "hostname", "ip", "agent_id", "source", "environment",
		"business_unit", "owner", "lifecycle", "tags", "first_seen", "last_seen",
	})
	for _, a := range assets {
		cw.Write([]string{
			a.AssetKey, a.AssetType, a.Name, a.Version, a.Format, a.Vendor, a.Arch,
			a.Location, a.Hostname, a.IP, a.AgentID, a.Source, a.Environment,
			a.BusinessUnit, a.Owner, a.Lifecycle, strings.Join(a.Tags, ";"),
			a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
}

// importAssets accepts an external CMDB ledger as JSON or CSV and upserts it
// into the asset table with source='cmdb_import'. mode=full retires imported
// assets absent from the payload.
func (s *RESTServer) importAssets(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		contentType := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(contentType, "text/csv") {
			format = "csv"
		} else {
			format = "json"
		}
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	full := mode == "full"

	var items []store.ExternalAssetInput
	var err error
	switch format {
	case "csv":
		items, err = parseExternalImportCSV(r.Body)
	default:
		items, err = parseExternalImportJSON(r.Body)
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(items) > maxExternalImportRows {
		writeError(w, 400, fmt.Sprintf("import exceeds %d rows", maxExternalImportRows))
		return
	}

	res, err := s.store.ImportExternalAssets(r.Context(), items, full, requestActor(r))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"format":    format,
		"mode":      mode,
		"imported":  res.Imported,
		"updated":   res.Updated,
		"retired":   res.Retired,
		"changes":   res.Changes,
		"errors":    res.Errors,
		"row_count": len(items),
	})
}

// reconcileReport returns the external-vs-scanned host matching summary.
func (s *RESTServer) reconcileReport(w http.ResponseWriter, r *http.Request) {
	report, err := s.store.CMDBReconcileReport(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, report)
}

// parseExternalImportJSON accepts either {"assets":[...]} or a bare array of
// external asset rows.
func parseExternalImportJSON(r io.Reader) ([]store.ExternalAssetInput, error) {
	data, err := readBodyLimited(r, 8<<20)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Assets []store.ExternalAssetInput `json:"assets"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Assets != nil {
		return wrapper.Assets, nil
	}
	var arr []store.ExternalAssetInput
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("invalid JSON: expected {\"assets\":[...]} or [...]")
	}
	return arr, nil
}

// parseExternalImportCSV parses an exported CSV ledger back into rows. The
// tags field is a ";"-separated list inside a single CSV column.
func parseExternalImportCSV(r io.Reader) ([]store.ExternalAssetInput, error) {
	data, err := readBodyLimited(r, 8<<20)
	if err != nil {
		return nil, err
	}
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV: %w", err)
	}
	if len(records) < 1 {
		return nil, fmt.Errorf("CSV must have a header row")
	}
	header := make([]string, len(records[0]))
	for i, h := range records[0] {
		header[i] = strings.ToLower(strings.TrimSpace(h))
	}
	var out []store.ExternalAssetInput
	for i, rec := range records[1:] {
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		row := make(map[string]string, len(header))
		for j, h := range header {
			if j < len(rec) {
				row[h] = strings.TrimSpace(rec[j])
			}
		}
		item, err := externalInputFromMap(row)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+2, err)
		}
		out = append(out, item)
	}
	return out, nil
}

func readBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
}

func externalInputFromMap(row map[string]string) (store.ExternalAssetInput, error) {
	item := store.ExternalAssetInput{
		AssetKey:     row["asset_key"],
		Name:         row["name"],
		Version:      row["version"],
		AssetType:    row["asset_type"],
		Hostname:     row["hostname"],
		IP:           row["ip"],
		Format:       row["format"],
		Vendor:       row["vendor"],
		Arch:         row["arch"],
		Location:     row["location"],
		Environment:  row["environment"],
		BusinessUnit: row["business_unit"],
		Owner:        row["owner"],
		Lifecycle:    row["lifecycle"],
	}
	if raw := row["tags"]; raw != "" {
		if strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var tags []string
			if err := json.Unmarshal([]byte(raw), &tags); err == nil {
				item.Tags = tags
			}
		}
		if item.Tags == nil {
			for _, t := range strings.Split(raw, ";") {
				if t = strings.TrimSpace(t); t != "" {
					item.Tags = append(item.Tags, t)
				}
			}
		}
	}
	if strings.TrimSpace(item.Name) == "" {
		return item, fmt.Errorf("name is required")
	}
	return item, nil
}
