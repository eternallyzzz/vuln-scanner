package collector

import (
	"context"
	"os/exec"
	"time"
)

// DefaultCommandTimeout bounds every telemetry command so one hung utility
// cannot stall a full inventory sync.
const DefaultCommandTimeout = 5 * time.Second

// RunTimeout executes a command with a bounded timeout and returns stdout.
func RunTimeout(name string, args ...string) ([]byte, error) {
	return RunTimeoutWith(DefaultCommandTimeout, name, args...)
}

// RunTimeoutWith executes a command with a specific timeout and returns stdout.
func RunTimeoutWith(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// RunCombinedTimeoutWith executes a command with a bounded timeout and
// returns both stdout and stderr so callers can include diagnostics when a
// command fails.
func RunCombinedTimeoutWith(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
