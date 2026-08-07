package agent

import (
	"bytes"
	"context"
	"errors"
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
		// Writers instead of StdoutPipe/StderrPipe: os/exec guarantees the
		// copy goroutines have delivered all output before Wait returns,
		// avoiding the pipe-close race that can drop the tail of the output.
		stdoutW := newStreamWriter("stdout", out, sink, &cancelled, cancel)
		stderrW := newStreamWriter("stderr", out, sink, &cancelled, cancel)
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW
		if err := cmd.Start(); err != nil {
			return -1, out.String(), err
		}
		go func() {
			<-runCtx.Done()
			if cmd.Process != nil {
				killProcessTree(cmd.Process.Pid)
			}
		}()
		waitErr := cmd.Wait()
		stdoutW.flush()
		stderrW.flush()
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

// streamWriter is a line-buffered stdout/stderr sink used directly as
// cmd.Stdout/cmd.Stderr. It writes into the combined buffer and pushes
// line-buffered chunks to the progress sink; the trailing unterminated line
// is flushed after the command exits.
type streamWriter struct {
	stream    string
	out       *syncBuffer
	sink      progressSink
	cancelled *atomic.Bool
	cancel    context.CancelFunc
	pending   []byte
}

func newStreamWriter(stream string, out *syncBuffer, sink progressSink, cancelled *atomic.Bool, cancel context.CancelFunc) *streamWriter {
	return &streamWriter{
		stream:    stream,
		out:       out,
		sink:      sink,
		cancelled: cancelled,
		cancel:    cancel,
	}
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for {
		idx := bytes.IndexByte(w.pending, '\n')
		if idx < 0 {
			return len(p), nil
		}
		w.emitLine(w.pending[:idx+1])
		w.pending = w.pending[idx+1:]
	}
}

func (w *streamWriter) flush() {
	if len(w.pending) > 0 {
		w.emitLine(w.pending)
		w.pending = nil
	}
}

func (w *streamWriter) emitLine(line []byte) {
	if len(line) > maxEventChunkBytes {
		truncated := make([]byte, 0, maxEventChunkBytes+len("\n...[truncated]"))
		truncated = append(truncated, line[:maxEventChunkBytes]...)
		truncated = append(truncated, "\n...[truncated]"...)
		line = truncated
	}
	w.emit(line)
}

func (w *streamWriter) emit(chunk []byte) {
	s := string(chunk)
	w.out.WriteString(s)
	if w.sink != nil {
		req, err := w.sink(OutputChunk{Stream: w.stream, Data: s})
		if err != nil {
			slog.Warn("patch progress report failed", "stream", w.stream, "error", err)
		} else if req {
			w.cancelled.Store(true)
			w.cancel()
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
