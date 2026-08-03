package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

const (
	maxCampaignAgents = 200
	maxCampaignTasks  = 5000
)

var (
	errPatchDisabled     = errors.New("patch deployment is disabled")
	errNoAgentsMatch     = errors.New("no agents match the selection")
	errTaskLimitExceeded = errors.New("selection matches more than 5000 tasks; narrow the filters")
)

type campaignTaskPlan struct {
	AgentID  string
	Hostname string
	Asset    string
	FixType  string
	FixValue string
	Action   string
	CVEIDs   []string
	Command  string
	Commands [][]string
}

type campaignMatched struct {
	AgentID    string   `json:"agent_id"`
	Hostname   string   `json:"hostname"`
	AssetName  string   `json:"asset_name"`
	CVEIDs     []string `json:"cve_ids"`
	FixType    string   `json:"fix_type"`
	FixValue   string   `json:"fix_value"`
	Action     string   `json:"action"`
	Command    string   `json:"command"`
	Deployable bool     `json:"deployable"`
}

type campaignGenerationResult struct {
	DryRun   bool                `json:"dry_run,omitempty"`
	Matched  []campaignMatched   `json:"matched,omitempty"`
	Campaign store.PatchCampaign `json:"campaign,omitempty"`
	Created  int                 `json:"created"`
	Counts   map[string]int      `json:"counts"`
	Tasks    []store.PatchTask   `json:"tasks,omitempty"`
	Errors   []string            `json:"errors"`
}

// runCampaignGeneration is the shared batch task generation pipeline used by
// both the HTTP handler and alert-driven remediation. It validates the
// input, resolves agents/assets, dedupes against open tasks, and either
// previews (dry_run) or atomically creates a campaign with its tasks.
func runCampaignGeneration(ctx context.Context, st *store.Store, patchCfg *patch.Config,
	in campaignGenerateInput, createdBy string) (campaignGenerationResult, error) {
	res := campaignGenerationResult{Counts: map[string]int{}}
	if patchCfg == nil || !patchCfg.Enabled {
		return res, errPatchDisabled
	}
	if err := validateCampaignInput(&in); err != nil {
		return res, err
	}
	windowStart, windowEnd, err := parseCampaignWindow(in.WindowStart, in.WindowEnd)
	if err != nil {
		return res, err
	}

	agentSet := map[string]bool{}
	if len(in.AgentIDs) > 0 {
		for _, id := range in.AgentIDs {
			agentSet[id] = true
		}
	} else {
		ids, err := st.AgentsByAssetFilters(ctx, in.Tags, in.Environments, in.AssetNames)
		if err != nil {
			return res, err
		}
		for _, id := range ids {
			agentSet[id] = true
		}
	}
	if len(agentSet) == 0 {
		return res, errNoAgentsMatch
	}

	agents := make([]store.Agent, 0, len(agentSet))
	var agentErrors []string
	for id := range agentSet {
		ag, err := st.GetAgent(ctx, id)
		if err != nil || ag == nil {
			if errors.Is(err, pgx.ErrNoRows) {
				agentErrors = append(agentErrors, "agent not found: "+id)
				continue
			}
			return res, err
		}
		agents = append(agents, *ag)
	}
	if len(agents) == 0 {
		return res, fmt.Errorf("%w: %s", errNoAgentsMatch, strings.Join(agentErrors, "; "))
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })

	approvalRequired := patchCfg.DefaultApprovalRequired
	if in.ApprovalRequired != nil {
		approvalRequired = *in.ApprovalRequired
	}
	needMeta := len(in.Tags) > 0 || len(in.Environments) > 0

	var plans []campaignTaskPlan
	var buildErrors []string
	skippedDedup, skippedNonDeployable := 0, 0
	for _, ag := range agents {
		recs, err := st.GetAgentRecommendations(ctx, ag.ID)
		if err != nil {
			buildErrors = append(buildErrors, ag.ID+": recommendations: "+err.Error())
			continue
		}
		if len(recs) == 0 {
			continue
		}
		var metaMap map[string]store.AssetMeta
		if needMeta {
			metaMap, err = st.AssetMetaByAgent(ctx, ag.ID)
			if err != nil {
				buildErrors = append(buildErrors, ag.ID+": asset meta: "+err.Error())
				continue
			}
		}
		cveMap, err := st.ActiveCVEsByAssetFiltered(ctx, ag.ID, in.MinSeverity, in.MinCVSS, in.CVEIDs)
		if err != nil {
			buildErrors = append(buildErrors, ag.ID+": cve lookup: "+err.Error())
			continue
		}
		for _, rec := range recs {
			meta := store.AssetMeta{}
			if metaMap != nil {
				meta = metaMap[rec.AssetName]
			}
			if !matchesAssetFilters(rec.AssetName, meta, in.Tags, in.Environments, in.AssetNames) {
				continue
			}
			cves := cveMap[rec.AssetName]
			if len(cves) == 0 {
				continue
			}
			cmd, err := patch.BuildCommandForAgent(patchCfg, rec.FixType, rec.FixedVersion,
				rec.AssetName, rec.ReferenceURL, ag.OSType, ag.OSVersion)
			if err != nil {
				buildErrors = append(buildErrors, fmt.Sprintf("%s/%s: %v", ag.ID, rec.AssetName, err))
				continue
			}
			if !cmd.Deployable {
				skippedNonDeployable++
				continue
			}
			open, err := st.HasOpenPatchTask(ctx, ag.ID, rec.AssetName)
			if err != nil {
				buildErrors = append(buildErrors, fmt.Sprintf("%s/%s: dedupe check: %v", ag.ID, rec.AssetName, err))
				continue
			}
			if open {
				skippedDedup++
				continue
			}
			plans = append(plans, campaignTaskPlan{
				AgentID: ag.ID, Hostname: ag.Hostname, Asset: rec.AssetName,
				FixType: rec.FixType, FixValue: rec.FixValue, Action: rec.Action,
				CVEIDs: cves, Command: cmd.Display, Commands: cmd.ArgvLists,
			})
			if len(plans) > maxCampaignTasks {
				return res, errTaskLimitExceeded
			}
		}
	}

	res.Counts = map[string]int{
		"matched": len(plans), "skipped_dedup": skippedDedup,
		"skipped_non_deployable": skippedNonDeployable,
	}
	res.Errors = buildErrors
	if in.DryRun {
		res.DryRun = true
		for _, p := range plans {
			res.Matched = append(res.Matched, campaignMatched{
				AgentID: p.AgentID, Hostname: p.Hostname, AssetName: p.Asset,
				CVEIDs: p.CVEIDs, FixType: p.FixType, FixValue: p.FixValue,
				Action: p.Action, Command: p.Command, Deployable: true,
			})
		}
		return res, nil
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "campaign-" + time.Now().Format("20060102-150405")
	}
	filters := map[string]interface{}{
		"name": name, "agent_ids": in.AgentIDs, "tags": in.Tags,
		"environments": in.Environments, "asset_names": in.AssetNames,
		"cve_ids": in.CVEIDs, "min_severity": in.MinSeverity, "min_cvss": in.MinCVSS,
		"approval_required": approvalRequired,
		"window_start":      in.WindowStart, "window_end": in.WindowEnd,
	}
	filtersJSON, _ := json.Marshal(filters)

	tasks := make([]store.CampaignTaskInput, 0, len(plans))
	for _, p := range plans {
		tasks = append(tasks, store.CampaignTaskInput{
			AgentID: p.AgentID, AssetName: p.Asset, FixType: p.FixType,
			FixValue: p.FixValue, Action: p.Action, CVEIDs: p.CVEIDs,
			Command: p.Command, Commands: p.Commands,
			ApprovalRequired: approvalRequired, WindowStart: windowStart,
			WindowEnd: windowEnd, CreatedBy: createdBy,
		})
	}
	campaign, created, err := st.CreatePatchCampaignWithTasks(ctx, name, filtersJSON, createdBy, tasks)
	if err != nil {
		return res, err
	}
	res.Campaign = campaign
	res.Created = len(tasks)
	if len(created) > 100 {
		created = created[:100]
	}
	res.Tasks = created
	return res, nil
}
