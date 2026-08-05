//go:build !windows && !linux && !darwin

package compliance

import (
	"context"

	"vuln-scanner/internal/collector"
)

// CollectFacts returns empty facts on unsupported platforms so agent builds
// for other GOOS values still compile; Evaluate then produces no checks and
// the scheduler skips the compliance sync.
func CollectFacts(_ context.Context, _ collector.SystemInfo) Facts {
	return Facts{}
}
