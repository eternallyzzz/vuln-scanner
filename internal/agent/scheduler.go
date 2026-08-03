package agent

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"

	"github.com/golang-jwt/jwt/v5"
)

type Scheduler struct {
	cfg        *Config
	client     *Client
	collect    collector.Collector
	ticker     *time.Ticker
	done       chan struct{}
	lastAssets map[string]string
}

func NewScheduler(cfg *Config, client *Client, col collector.Collector) *Scheduler {
	return &Scheduler{
		cfg:     cfg,
		client:  client,
		collect: col,
		done:    make(chan struct{}),
	}
}

func (s *Scheduler) Start(ctx context.Context) error {
	interval := time.Duration(s.cfg.Agent.CollectionInterval) * time.Second
	if interval < 60*time.Second {
		interval = 60 * time.Second
	}
	heartbeatInterval := 30 * time.Second
	patchInterval := 60 * time.Second

	s.ticker = time.NewTicker(interval)
	hbTicker := time.NewTicker(heartbeatInterval)
	patchTicker := time.NewTicker(patchInterval)
	defer patchTicker.Stop()

	s.doFullSync(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		case <-hbTicker.C:
			if err := s.client.Heartbeat(ctx, 0); err != nil {
				slog.Warn("heartbeat failed", "error", err)
			}
		case <-s.ticker.C:
			if s.tokenExpiringSoon() {
				if err := s.client.RefreshToken(ctx); err != nil {
					slog.Warn("token refresh failed", "error", err)
				}
			}
			s.doIncrementalSync(ctx)
		case <-patchTicker.C:
			if s.cfg.Agent.PatchEnabled {
				s.doPatchLoop(ctx)
			}
		}
	}
}

func (s *Scheduler) doPatchLoop(ctx context.Context) {
	tasks, err := s.client.FetchPatchTasks(ctx)
	if err != nil {
		slog.Warn("fetch patch tasks failed", "error", err)
		return
	}
	for _, task := range tasks {
		timeout := time.Duration(s.cfg.Agent.PatchTimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 600 * time.Second
		}
		if task.GetDryRun() {
			slog.Info("patch task dry-run", "task_id", task.GetId(),
				"asset", task.GetAssetName(), "command", task.GetCommand())
			if err := s.client.ReportPatchTask(ctx, task.GetId(), "success", 0,
				"dry-run: execution skipped"); err != nil {
				slog.Warn("report patch task failed", "task_id", task.GetId(), "error", err)
			}
			continue
		}

		slog.Info("patch task executing", "task_id", task.GetId(),
			"asset", task.GetAssetName(), "command", task.GetCommand())
		var argvLists [][]string
		for _, c := range task.GetCommands() {
			if c != nil {
				argvLists = append(argvLists, c.GetArgv())
			}
		}
		exitCode, output, err := executeCommands(ctx, argvLists, timeout)
		status := "success"
		if err != nil {
			status = "failed"
			slog.Error("patch task failed", "task_id", task.GetId(),
				"exit_code", exitCode, "error", err)
		}
		if err := s.client.ReportPatchTask(ctx, task.GetId(), status, exitCode, output); err != nil {
			slog.Warn("report patch task failed", "task_id", task.GetId(), "error", err)
		}
	}
}

func (s *Scheduler) Stop() {
	close(s.done)
	if s.ticker != nil {
		s.ticker.Stop()
	}
}

func (s *Scheduler) RunOnce(ctx context.Context) ([]collector.Asset, collector.SystemInfo) {
	assets, sys := s.doFullSync(ctx)
	return assets, sys
}

func (s *Scheduler) doFullSync(ctx context.Context) ([]collector.Asset, collector.SystemInfo) {
	slog.Info("starting full inventory sync")
	assets, sys, err := collector.All(ctx, s.collect)
	if err != nil {
		slog.Error("full sync collection failed", "error", err)
		return nil, collector.SystemInfo{}
	}
	assets = dedupeAssets(assets)

	var pbAssets []*pb.Asset
	for _, a := range assets {
		pbAssets = append(pbAssets, assetToPb(a))
	}

	if err := s.client.SyncInventory(ctx, pbAssets, pb.SyncMode_FULL); err != nil {
		slog.Error("full sync rpc failed", "error", err)
		return assets, sys
	}

	s.lastAssets = make(map[string]string, len(assets))
	for _, a := range assets {
		s.lastAssets[assetSyncKey(a)] = a.Version
	}

	slog.Info("full sync completed", "assets", len(pbAssets), "os", sys.OS, "version", sys.Version)
	return assets, sys
}

func (s *Scheduler) doIncrementalSync(ctx context.Context) {
	slog.Info("starting incremental inventory sync")
	assets, _, err := collector.All(ctx, s.collect)
	if err != nil {
		slog.Error("incremental sync collection failed", "error", err)
		return
	}
	assets = dedupeAssets(assets)

	current := make(map[string]string, len(assets))
	for _, a := range assets {
		current[assetSyncKey(a)] = a.Version
	}

	var changed []*pb.Asset
	for _, a := range assets {
		prev, existed := s.lastAssets[assetSyncKey(a)]
		if !existed || prev != a.Version {
			changed = append(changed, assetToPb(a))
		}
	}

	if len(changed) == 0 {
		slog.Info("incremental sync: no changes")
		s.lastAssets = current
		return
	}

	if err := s.client.SyncInventory(ctx, changed, pb.SyncMode_INCREMENTAL); err != nil {
		slog.Warn("incremental sync rpc failed", "error", err)
		return
	}

	s.lastAssets = current
	names := make([]string, 0, len(changed))
	for _, a := range changed {
		names = append(names, a.GetName()+"@"+a.GetVersion())
	}
	slog.Info("incremental sync completed", "changed", len(changed), "total", len(assets), "assets", strings.Join(names, ", "))
}

func (s *Scheduler) tokenExpiringSoon() bool {
	if s.cfg.Agent.Token == "" {
		return false
	}
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(s.cfg.Agent.Token, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	remaining := time.Until(time.Unix(int64(exp), 0))
	return remaining < 1*time.Hour
}

func assetToPb(a collector.Asset) *pb.Asset {
	assetType := pb.AssetType_PACKAGE
	switch a.Type {
	case "HOTFIX":
		assetType = pb.AssetType_HOTFIX
	case "OS":
		assetType = pb.AssetType_OS
	}
	return &pb.Asset{
		Name:        a.Name,
		Version:     a.Version,
		Arch:        a.Arch,
		Format:      a.Format,
		Vendor:      a.Vendor,
		Location:    a.Location,
		InstallDate: a.InstallDate,
		Status:      a.Status,
		Type:        assetType,
	}
}

// assetSyncKey identifies an inventory entry across sync cycles. Name alone is
// not enough: the same name can appear multiple times with different formats
// or locations (e.g. a dpkg "git" and an npm extension "git").
func assetSyncKey(a collector.Asset) string {
	return a.Name + "\x00" + a.Format + "\x00" + a.Location + "\x00" + a.Arch
}

// dedupeAssets collapses entries that share the same sync identity, keeping
// the entry with the highest version. Without this, registry/AppX collectors
// can emit the same package several times with different variants or stale
// versions, which would make every incremental cycle report spurious changes.
func dedupeAssets(assets []collector.Asset) []collector.Asset {
	best := make(map[string]int, len(assets))
	out := make([]collector.Asset, 0, len(assets))
	for _, a := range assets {
		key := assetSyncKey(a)
		if idx, ok := best[key]; ok {
			if versionNewer(a.Version, out[idx].Version) {
				out[idx] = a
			}
			continue
		}
		best[key] = len(out)
		out = append(out, a)
	}
	return out
}

func versionNewer(a, b string) bool {
	if a == b {
		return false
	}
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	aSegs := strings.Split(a, ".")
	bSegs := strings.Split(b, ".")
	for i := 0; i < len(aSegs) || i < len(bSegs); i++ {
		var aNum, bNum int64
		if i < len(aSegs) {
			aNum, _ = strconv.ParseInt(aSegs[i], 10, 64)
		}
		if i < len(bSegs) {
			bNum, _ = strconv.ParseInt(bSegs[i], 10, 64)
		}
		if aNum != bNum {
			return aNum > bNum
		}
	}
	return false
}
