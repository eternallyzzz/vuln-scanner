package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vuln-scanner/internal/store"
)

const (
	postPatchFollowUpMaxDepth    = 3
	postPatchFollowUpMaxAttempts = 3
)

// postPatchFollowUpLoop is the single-runner loop that turns failed
// post-patch verifications with missing fixes into follow-up campaigns.
func (w *Worker) postPatchFollowUpLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	slog.Info("post-patch follow-up loop started", "worker", w.workerID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
		case <-w.wakeCh:
		}
		w.processPostPatchFollowUps(ctx)
	}
}

func (w *Worker) processPostPatchFollowUps(ctx context.Context) {
	if w.patchCfg == nil || !w.patchCfg.Enabled {
		return
	}
	tasks, err := w.store.ListPendingPostPatchFollowUps(ctx)
	if err != nil {
		slog.Warn("post-patch follow-up list failed", "error", err)
		return
	}
	for _, t := range tasks {
		w.processPostPatchFollowUp(ctx, t)
	}
}

func (w *Worker) processPostPatchFollowUp(ctx context.Context, t store.PatchTask) {
	if t.PostPatchFollowUpDepth >= postPatchFollowUpMaxDepth {
		_ = w.store.MarkPostPatchFollowUpSkipped(ctx, t.ID, "max follow-up depth reached")
		return
	}
	if t.PostPatchFollowUpAttempts >= postPatchFollowUpMaxAttempts {
		_ = w.store.MarkPostPatchFollowUpSkipped(ctx, t.ID, "max follow-up attempts reached")
		return
	}
	ok, err := w.store.BeginPostPatchFollowUpAttempt(ctx, t.ID)
	if err != nil {
		slog.Warn("post-patch follow-up claim failed", "task_id", t.ID, "error", err)
		return
	}
	if !ok {
		return
	}

	missing, err := w.store.MissingFixesForTask(ctx, t)
	if err != nil {
		slog.Warn("post-patch follow-up missing fixes failed", "task_id", t.ID, "error", err)
		return
	}
	if len(missing) == 0 {
		_ = w.store.MarkPostPatchFollowUpSkipped(ctx, t.ID, "no missing fixes")
		return
	}

	agent, err := w.store.GetAgent(ctx, t.AgentID)
	if err != nil {
		slog.Warn("post-patch follow-up agent lookup failed", "task_id", t.ID, "error", err)
		return
	}
	if agent == nil {
		_ = w.store.MarkPostPatchFollowUpSkipped(ctx, t.ID, "agent not found")
		return
	}
	approval := w.patchCfg.DefaultApprovalRequired
	in := campaignGenerateInput{
		Name:                 fmt.Sprintf("post-patch-followup-%d", t.ID),
		AgentIDs:             []string{t.AgentID},
		AssetNames:           []string{t.AssetName},
		CVEIDs:               t.CVEIDs,
		ApprovalRequired:     &approval,
		FollowUpSourceTaskID: t.ID,
	}
	res, err := runCampaignGeneration(ctx, w.store, w.patchCfg, in, "post-patch-followup", agent.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrPostPatchFollowUpAlreadyHandled) {
			return
		}
		slog.Warn("post-patch follow-up generation failed", "task_id", t.ID, "error", err)
		return
	}
	if res.Created > 0 {
		slog.Info("post-patch follow-up campaign created", "task_id", t.ID,
			"campaign_id", res.Campaign.ID, "tasks", res.Created)
		return
	}
	_ = w.store.MarkPostPatchFollowUpSkipped(ctx, t.ID, followUpSkipReason(res))
}

func followUpSkipReason(res campaignGenerationResult) string {
	if len(res.Errors) > 0 {
		return "generation errors: " + strings.Join(res.Errors, "; ")
	}
	if res.Counts["skipped_dedup"] > 0 {
		return "duplicate: open patch task exists"
	}
	if res.Counts["skipped_non_deployable"] > 0 {
		return "non-deployable fix"
	}
	return "no matching fix"
}
