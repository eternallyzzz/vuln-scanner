package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Store) CreateAnalysisLog(ctx context.Context, a *AnalysisLog) error {
	cveIDs, err := json.Marshal(a.CVEIDs)
	if err != nil {
		return fmt.Errorf("marshal cve_ids: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO analysis_logs (id, agent_id, cve_ids, prompt, response, summary, provider, model, tokens_used, duration_ms, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, a.ID, a.AgentID, cveIDs, a.Prompt, a.Response, a.Summary, a.Provider, a.Model, a.TokensUsed, a.DurationMS, time.Now())
	return err
}

func (s *Store) GetAnalysisLog(ctx context.Context, id string) (*AnalysisLog, error) {
	var a AnalysisLog
	var rawCVEIDs []byte

	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, cve_ids, prompt, response, summary, provider, model, tokens_used, duration_ms, created_at
		FROM analysis_logs WHERE id=$1
	`, id).Scan(&a.ID, &a.AgentID, &rawCVEIDs, &a.Prompt, &a.Response, &a.Summary,
		&a.Provider, &a.Model, &a.TokensUsed, &a.DurationMS, &a.CreatedAt)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(rawCVEIDs, &a.CVEIDs); err != nil {
		return nil, fmt.Errorf("unmarshal cve_ids: %w", err)
	}
	return &a, nil
}

func (s *Store) GetAgentAnalysisLogs(ctx context.Context, agentID string, limit int) ([]AnalysisLog, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, cve_ids, prompt, response, summary, provider, model, tokens_used, duration_ms, created_at
		FROM analysis_logs WHERE agent_id=$1 ORDER BY created_at DESC LIMIT $2
	`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AnalysisLog
	for rows.Next() {
		var a AnalysisLog
		var rawCVEIDs []byte
		if err := rows.Scan(&a.ID, &a.AgentID, &rawCVEIDs, &a.Prompt, &a.Response,
			&a.Summary, &a.Provider, &a.Model, &a.TokensUsed, &a.DurationMS, &a.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal(rawCVEIDs, &a.CVEIDs)
		logs = append(logs, a)
	}
	return logs, nil
}
