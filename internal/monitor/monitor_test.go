package monitor

import (
	"encoding/json"
	"testing"
)

func TestDiffFilesWarmUpAndDrift(t *testing.T) {
	prev := map[string]FileFact{}
	cur := map[string]FileFact{
		"/etc/ssh/sshd_config": {Path: "/etc/ssh/sshd_config", SHA256: "a", SizeBytes: 10, Mode: "0644"},
	}
	if drifts := DiffFiles(prev, cur); len(drifts) != 0 {
		t.Fatalf("warm-up must produce no drifts, got %+v", drifts)
	}

	prev = map[string]FileFact{
		"/etc/ssh/sshd_config": {Path: "/etc/ssh/sshd_config", SHA256: "a", SizeBytes: 10, Mode: "0644"},
		"/etc/passwd":          {Path: "/etc/passwd", SHA256: "b", SizeBytes: 20, Mode: "0644"},
	}
	cur = map[string]FileFact{
		"/etc/ssh/sshd_config": {Path: "/etc/ssh/sshd_config", SHA256: "z", SizeBytes: 11, Mode: "0644"},
		"/etc/newfile":         {Path: "/etc/newfile", SHA256: "c", SizeBytes: 1, Mode: "0600"},
	}
	drifts := DiffFiles(prev, cur)
	if len(drifts) != 3 {
		t.Fatalf("drifts = %d, want 3 (modified + added + removed)", len(drifts))
	}
	byKey := map[string]Drift{}
	for _, d := range drifts {
		byKey[d.Key] = d
	}
	if byKey["/etc/ssh/sshd_config"].Kind != "modified" {
		t.Fatalf("sshd drift = %+v", byKey["/etc/ssh/sshd_config"])
	}
	if byKey["/etc/newfile"].Kind != "added" {
		t.Fatalf("newfile drift = %+v", byKey["/etc/newfile"])
	}
	if byKey["/etc/passwd"].Kind != "removed" {
		t.Fatalf("passwd drift = %+v", byKey["/etc/passwd"])
	}
	if SeverityForPath("/etc/ssh/sshd_config") != "HIGH" || SeverityForPath("/etc/passwd") != "HIGH" {
		t.Fatal("sensitive paths must be HIGH")
	}
	if SeverityForPath("/opt/app/config.json") != "MEDIUM" {
		t.Fatal("non-sensitive path must be MEDIUM")
	}
}

func TestDiffBehavior(t *testing.T) {
	prev := map[string]map[string]json.RawMessage{}
	cur := map[string]map[string]json.RawMessage{
		"accounts": {"domain\\alice": json.RawMessage(`{"name":"alice"}`)},
	}
	if drifts := DiffBehavior(prev, cur); len(drifts) != 0 {
		t.Fatalf("warm-up must produce no drifts, got %+v", drifts)
	}

	prev = map[string]map[string]json.RawMessage{
		"accounts": {
			"domain\\alice": json.RawMessage(`{"name": "alice"}`),
		},
	}
	cur = map[string]map[string]json.RawMessage{
		"accounts": {
			"domain\\alice": json.RawMessage(`{"name":"alice"}`),
		},
	}
	if drifts := DiffBehavior(prev, cur); len(drifts) != 0 {
		t.Fatalf("JSON formatting differences must not produce drift, got %+v", drifts)
	}

	prev = map[string]map[string]json.RawMessage{
		"accounts": {
			"domain\\alice": json.RawMessage(`{"name":"alice"}`),
			"domain\\bob":   json.RawMessage(`{"name":"bob"}`),
		},
	}
	cur = map[string]map[string]json.RawMessage{
		"accounts": {
			"domain\\alice":   json.RawMessage(`{"name":"alice2"}`),
			"domain\\mallory": json.RawMessage(`{"name":"mallory"}`),
		},
	}
	drifts := DiffBehavior(prev, cur)
	if len(drifts) != 3 {
		t.Fatalf("drifts = %d, want 3", len(drifts))
	}
	byKey := map[string]Drift{}
	for _, d := range drifts {
		byKey[d.Key] = d
	}
	if byKey["domain\\alice"].Kind != "modified" {
		t.Fatalf("alice drift = %+v", byKey["domain\\alice"])
	}
	if byKey["domain\\mallory"].Kind != "added" {
		t.Fatalf("mallory drift = %+v", byKey["domain\\mallory"])
	}
	if byKey["domain\\bob"].Kind != "removed" {
		t.Fatalf("bob drift = %+v", byKey["domain\\bob"])
	}
	if byKey["domain\\mallory"].Severity != "HIGH" {
		t.Fatalf("account severity = %q, want HIGH", byKey["domain\\mallory"].Severity)
	}
}
