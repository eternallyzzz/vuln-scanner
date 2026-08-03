package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	code, output, err := executeCommands(t.Context(), [][]string{shellArgv("echo", "hello")}, 10*time.Second)
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
	code, _, err := executeCommands(t.Context(), [][]string{argv}, 10*time.Second)
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
	code, _, err := executeCommands(t.Context(), [][]string{failing, later}, 10*time.Second)
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
	_, output, err := executeCommands(t.Context(), [][]string{argv}, 10*time.Second)
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
	code, _, err := executeCommands(t.Context(), [][]string{argv}, 800*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if code != -1 {
		t.Fatalf("expected -1 on timeout, got %d", code)
	}
}
