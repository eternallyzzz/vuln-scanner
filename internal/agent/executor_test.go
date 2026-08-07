package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func shellArgv(args ...string) []string {
	if runtime.GOOS == "windows" {
		return append([]string{"cmd", "/c"}, args...)
	}
	return append([]string{"sh", "-c"}, strings.Join(args, " "))
}

func TestExecuteCommandsSuccess(t *testing.T) {
	code, output, err := executeCommandsStreaming(context.Background(), [][]string{shellArgv("echo", "hello")}, 10*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(output, "hello") {
		t.Fatalf("unexpected output %q", output)
	}
}

func TestExecuteCommandsFailure(t *testing.T) {
	var argv []string
	if runtime.GOOS == "windows" {
		argv = []string{"cmd", "/c", "exit", "3"}
	} else {
		argv = []string{"sh", "-c", "exit 3"}
	}
	code, _, err := executeCommandsStreaming(context.Background(), [][]string{argv}, 10*time.Second, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if code != 3 {
		t.Fatalf("expected exit 3, got %d", code)
	}
}

func TestExecuteCommandsStopsOnFirstFailure(t *testing.T) {
	failing := shellArgv("exit", "7")
	later := shellArgv("echo", "must-not-run")
	code, _, err := executeCommandsStreaming(context.Background(), [][]string{failing, later}, 10*time.Second, nil)
	if err == nil || code != 7 {
		t.Fatalf("expected exit 7, got %d err %v", code, err)
	}
}

func TestExecuteCommandsTruncatesOutput(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.txt")
	os.WriteFile(big, []byte(strings.Repeat("x", 70*1024)), 0644)
	var argv []string
	if runtime.GOOS == "windows" {
		argv = []string{"cmd", "/c", "type", big}
	} else {
		argv = []string{"sh", "-c", "cat " + big}
	}
	_, output, err := executeCommandsStreaming(context.Background(), [][]string{argv}, 10*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) > maxOutputBytes+64 {
		t.Fatalf("output not truncated: %d bytes", len(output))
	}
	if !strings.HasSuffix(output, "...[truncated]") {
		t.Fatalf("missing truncation marker")
	}
}

func TestExecuteCommandsTimeout(t *testing.T) {
	var argv []string
	if runtime.GOOS == "windows" {
		argv = []string{"cmd", "/c", "ping", "-n", "4", "127.0.0.1"}
	} else {
		argv = []string{"sh", "-c", "sleep 5"}
	}
	code, _, err := executeCommandsStreaming(context.Background(), [][]string{argv}, 800*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if code != -1 {
		t.Fatalf("expected -1 on timeout, got %d", code)
	}
}

func TestExecuteCommandsStreamsOutput(t *testing.T) {
	var mu sync.Mutex
	var chunks []OutputChunk
	sink := func(chunk OutputChunk) (bool, error) {
		mu.Lock()
		chunks = append(chunks, chunk)
		mu.Unlock()
		return false, nil
	}
	var argv []string
	if runtime.GOOS == "windows" {
		// "&" separates commands sequentially on Windows cmd.
		argv = []string{"cmd", "/c", "echo line1 & echo line2"}
	} else {
		// "&" would background the first echo on Unix, making chunk order
		// nondeterministic; use ";" for a deterministic sequential run.
		argv = []string{"sh", "-c", "echo line1; echo line2"}
	}
	_, output, err := executeCommandsStreaming(context.Background(), [][]string{argv}, 10*time.Second, sink)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	streamed := strings.Join(chunkData(chunks), "")
	mu.Unlock()
	if !strings.Contains(streamed, "line1") || !strings.Contains(streamed, "line2") {
		t.Fatalf("streamed chunks missing lines: %q", streamed)
	}
	if !strings.Contains(output, "line1") || !strings.Contains(output, "line2") {
		t.Fatalf("combined output missing lines: %q", output)
	}
}

func TestExecuteCommandsCancel(t *testing.T) {
	var sent atomic.Bool
	sink := func(chunk OutputChunk) (bool, error) {
		if strings.Contains(chunk.Data, "start") && !sent.Swap(true) {
			return true, nil
		}
		return false, nil
	}
	var argv []string
	if runtime.GOOS == "windows" {
		argv = []string{"cmd", "/c", "echo start & ping -n 10 127.0.0.1 > nul"}
	} else {
		argv = []string{"sh", "-c", "echo start; sleep 10"}
	}
	start := time.Now()
	code, _, err := executeCommandsStreaming(context.Background(), [][]string{argv}, 30*time.Second, sink)
	if !errors.Is(err, errCancelled) {
		t.Fatalf("expected errCancelled, got %v", err)
	}
	if code != -1 {
		t.Fatalf("expected -1 on cancel, got %d", code)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("cancel too slow: %v", elapsed)
	}
}

func chunkData(chunks []OutputChunk) []string {
	out := make([]string, 0, len(chunks))
	for _, c := range chunks {
		out = append(out, c.Data)
	}
	return out
}
