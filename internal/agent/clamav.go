package agent

import (
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"vuln-scanner/internal/collector"
)

// ParseClamAVOutput converts `clamscan --infected --no-summary` stdout into
// findings. Infected lines look like "<path>: <VirusName> FOUND"; summary
// and informational lines are skipped.
func ParseClamAVOutput(out string) []collector.EDRFinding {
	var findings []collector.EDRFinding
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasSuffix(line, " FOUND") {
			continue
		}
		idx := strings.LastIndex(line, ": ")
		if idx <= 0 {
			continue
		}
		path := strings.TrimSpace(line[:idx])
		virus := strings.TrimSpace(strings.TrimSuffix(line[idx+2:], " FOUND"))
		if path == "" || virus == "" {
			continue
		}
		findings = append(findings, collector.EDRFinding{
			Source:      "clamav",
			FindingType: "malware",
			Name:        virus,
			Severity:    "HIGH",
			Path:        path,
			Detail:      "clamscan infected file",
		})
	}
	return findings
}

// runClamAVScan executes a one-shot ClamAV scan of the configured paths when
// the binary exists. Windows is intentionally skipped: Defender product
// telemetry is already collected there and this round does not scan.
func runClamAVScan(ctx context.Context, paths []string, timeout time.Duration) []collector.EDRFinding {
	if runtime.GOOS == "windows" {
		return nil
	}
	if len(paths) == 0 {
		slog.Info("edr_scan enabled but no paths configured, skipping clamscan")
		return nil
	}
	exe, err := exec.LookPath("clamscan")
	if err != nil {
		slog.Info("clamscan not found, skipping EDR scan")
		return nil
	}
	args := append([]string{"--infected", "--no-summary"}, paths...)
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(scanCtx, exe, args...)
	out, err := cmd.Output()
	// clamscan exits 1 when infections are found; stdout still contains the
	// FOUND lines, so parse it even when the command reports that exit code.
	findings := ParseClamAVOutput(string(out))
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			slog.Warn("clamscan timed out", "timeout", timeout)
			return nil
		}
		if len(findings) == 0 {
			slog.Warn("clamscan failed", "error", err)
			return nil
		}
	}
	if len(findings) > 0 {
		slog.Info("clamscan completed", "infected", len(findings))
	}
	return findings
}
