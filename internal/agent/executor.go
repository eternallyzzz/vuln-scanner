package agent

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

const maxOutputBytes = 64 * 1024

// executeCommands runs each argv list sequentially using exec.Command (no
// shell interpolation) and returns the exit code and truncated combined
// output of the failing command, or of the last command on success.
func executeCommands(ctx context.Context, argvLists [][]string, timeout time.Duration) (int32, string, error) {
	if len(argvLists) == 0 {
		return 0, "no commands", nil
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastOutput string
	for _, argv := range argvLists {
		if len(argv) == 0 {
			continue
		}
		cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		lastOutput = truncateOutput(buf.String())
		if err != nil {
			code := int32(1)
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = int32(exitErr.ExitCode())
			}
			if runCtx.Err() != nil {
				code = -1
			}
			return code, lastOutput, err
		}
	}
	return 0, lastOutput, nil
}

func truncateOutput(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	return s[:maxOutputBytes] + "\n...[truncated]"
}
