package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"vuln-scanner/internal/server"
	"vuln-scanner/internal/store"
)

type Analyzer struct {
	providers []Provider
	store     *store.Store
	cfg       *server.LLMConfig
}

func NewAnalyzer(store_ *store.Store, cfg *server.LLMConfig) *Analyzer {
	if cfg == nil {
		return &Analyzer{store: store_, cfg: nil}
	}

	var providers []Provider
	if cfg.Provider == "openai" || cfg.Provider == "auto" {
		p := NewOpenAI(cfg.APIKey, cfg.Model, cfg.BaseURL)
		if p.Enabled() {
			providers = append(providers, p)
		}
	}
	if cfg.Provider == "anthropic" || cfg.Provider == "auto" {
		p := NewAnthropic(cfg.APIKey, cfg.Model, cfg.BaseURL)
		if p.Enabled() {
			providers = append(providers, p)
		}
	}

	return &Analyzer{
		providers: providers,
		store:     store_,
		cfg:       cfg,
	}
}

func (a *Analyzer) Enabled() bool {
	return len(a.providers) > 0
}

func (a *Analyzer) ShouldAutoAnalyze(severity string) bool {
	if !a.Enabled() || a.cfg == nil {
		return false
	}
	for _, s := range a.cfg.AutoAnalyze {
		if s == severity {
			return true
		}
	}
	return false
}

func (a *Analyzer) Analyze(ctx context.Context, agentID string, cveIDs []string, assetsJSON, cveResultsJSON string) (*store.AnalysisLog, error) {
	if !a.Enabled() {
		return nil, fmt.Errorf("llm not configured")
	}

	prompt := a.buildPrompt(assetsJSON, cveResultsJSON)

	startTime := time.Now()

	var lastErr error
	for _, p := range a.providers {
		resp, err := p.Chat(ctx, &Request{
			Messages: []Message{
				{Role: "system", Content: `You are a cybersecurity vulnerability analysis expert.
Analyze the provided asset inventory and CVE matches. For each vulnerability:
1. Categorize severity and assess real-world exploitability
2. Provide specific remediation steps
3. Mark as URGENT if remotely exploitable without authentication
4. Suggest workarounds when patches are not yet available

Respond in JSON format with fields: summary, recommendations (array of {cve_id, severity, priority, action, workaround})`},
				{Role: "user", Content: prompt},
			},
			MaxTokens: 4096,
		})

		if err != nil {
			slog.Error("llm provider failed", "provider", p.Name(), "error", err)
			lastErr = err
			continue
		}

		analysisLog := &store.AnalysisLog{
			ID:         generateLogID(agentID),
			AgentID:    agentID,
			CVEIDs:     cveIDs,
			Prompt:     prompt,
			Response:   resp.Content,
			Summary:    resp.Content,
			Provider:   p.Name(),
			Model:      resp.Model,
			TokensUsed: resp.TokensUsed,
			DurationMS: int(time.Since(startTime).Milliseconds()),
		}

		if err := a.store.CreateAnalysisLog(ctx, analysisLog); err != nil {
			slog.Error("failed to save analysis log", "error", err)
		}

		return analysisLog, nil
	}

	return nil, fmt.Errorf("all llm providers failed: %w", lastErr)
}

func (a *Analyzer) buildPrompt(assetsJSON, cveResultsJSON string) string {
	var assets interface{}
	var cves interface{}
	json.Unmarshal([]byte(assetsJSON), &assets)
	json.Unmarshal([]byte(cveResultsJSON), &cves)

	assetsPretty, _ := json.MarshalIndent(assets, "", "  ")
	cvesPretty, _ := json.MarshalIndent(cves, "", "  ")

	return fmt.Sprintf(`## Installed Assets
%s

## CVE Matches
%s

Analyze above and provide:
1. Priority ranking of vulnerabilities (URGENT > HIGH > MEDIUM > LOW)
2. For each critical vulnerability, provide actionable remediation steps
3. Identify any common root causes or patterns`, string(assetsPretty), string(cvesPretty))
}

func generateLogID(agentID string) string {
	return fmt.Sprintf("analysis-%s-%d", agentID[:min(8, len(agentID))], time.Now().UnixNano()%100000)
}
