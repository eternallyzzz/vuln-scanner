package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const maxOutputBytes = 64 * 1024

const (
	// progressHeartbeatInterval is the maximum silence between progress
	// reports, so an operator stop reaches a quiet command promptly.
	progressHeartbeatInterval = 2 * time.Second
	// maxEventChunkBytes caps a single progress event payload.
	maxEventChunkBytes = 64 * 1024
)

// errCancelled marks an execution stopped by an operator cancel request.
var errCancelled = errors.New("patch task cancelled")

// OutputChunk is one incremental execution event.
type OutputChunk struct {
	Stream string // stdout | stderr | heartbeat
	Data   string
}

// progressSink receives incremental output and heartbeats. It returns true
// when the server reports a cancel request. Report failures are tolerated:
// execution continues without progress rather than aborting the patch run.
type progressSink func(chunk OutputChunk) (cancelRequested bool, err error)

// executeCommandsStreaming runs each argv list sequentially, streaming
// stdout/stderr through sink (line-buffered, with a periodic heartbeat) and
// stops as soon as sink reports cancel or the context is done. It returns
// the final truncated combined output, an exit code, and errCancelled when
// the stop came from a cancel request.
func executeCommandsStreaming(ctx context.Context, argvLists [][]string, timeout time.Duration, sink progressSink) (int32, string, error) {
	if len(argvLists) == 0 {
		return 0, "no commands", nil
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := &syncBuffer{}
	heartbeatDone := make(chan struct{})
	var cancelled atomic.Bool
	if sink != nil {
		go progressHeartbeat(runCtx, heartbeatDone, sink, cancel, &cancelled)
	}
	defer close(heartbeatDone)

	var lastOutput string
	for _, argv := range argvLists {
		if len(argv) == 0 {
			continue
		}
		cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
		configureProcessGroup(cmd)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return -1, out.String(), err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return -1, out.String(), err
		}
		if err := cmd.Start(); err != nil {
			return -1, out.String(), err
		}
		go func() {
			<-runCtx.Done()
			if cmd.Process != nil {
				killProcessTree(cmd.Process.Pid)
			}
		}()
		var wg sync.WaitGroup
		wg.Add(2)
		go streamReader(stdout, "stdout", out, sink, &cancelled, cancel, &wg)
		go streamReader(stderr, "stderr", out, sink, &cancelled, cancel, &wg)
		waitErr := cmd.Wait()
		wg.Wait()
		lastOutput = out.String()
		if cancelled.Load() {
			return -1, lastOutput, errCancelled
		}
		if waitErr != nil {
			code := int32(1)
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				code = int32(exitErr.ExitCode())
			}
			if runCtx.Err() != nil {
				code = -1
			}
			return code, lastOutput, waitErr
		}
	}
	return 0, lastOutput, nil
}

// progressHeartbeat emits an empty event every interval so cancel requests
// reach commands that produce no output.
func progressHeartbeat(ctx context.Context, done chan struct{}, sink progressSink, cancel context.CancelFunc, cancelled *atomic.Bool) {
	ticker := time.NewTicker(progressHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := sink(OutputChunk{Stream: "heartbeat"})
			if err != nil {
				slog.Warn("patch progress heartbeat failed", "error", err)
				continue
			}
			if req {
				cancelled.Store(true)
				cancel()
			}
		}
	}
}

// streamReader copies one output stream into the combined buffer and pushes
// line-buffered chunks to the sink. Long lines are split at buffer bounds.
func streamReader(r io.Reader, stream string, out *syncBuffer, sink progressSink, cancelled *atomic.Bool, cancel context.CancelFunc, wg *sync.WaitGroup) {
	defer wg.Done()
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			chunk := line
			if len(chunk) > maxEventChunkBytes {
				chunk = chunk[:maxEventChunkBytes] + "\n...[truncated]"
			}
			out.WriteString(chunk)
			if sink != nil {
				req, serr := sink(OutputChunk{Stream: stream, Data: chunk})
				if serr != nil {
					slog.Warn("patch progress report failed", "stream", stream, "error", serr)
				} else if req {
					cancelled.Store(true)
					cancel()
				}
			}
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				continue
			}
			return
		}
	}
}

// syncBuffer is a goroutine-safe combined output buffer capped at
// maxOutputBytes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) WriteString(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := maxOutputBytes - b.buf.Len()
	if remaining <= 0 {
		return
	}
	if len(s) > remaining {
		s = s[:remaining]
	}
	b.buf.WriteString(s)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	if b.buf.Len() >= maxOutputBytes {
		s += "\n...[truncated]"
	}
	return s
}
