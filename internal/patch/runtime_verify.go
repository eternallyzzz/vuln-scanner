package patch

import (
	"encoding/json"
	"fmt"
	"strings"

	"vuln-scanner/internal/collector"
)

// RuntimeBaseline is the snapshot captured when a patch task is claimed: the
// services and processes known at that moment. Verification compares a fresh
// agent snapshot against it.
type RuntimeBaseline struct {
	Services  []collector.ServiceInfo `json:"services"`
	Processes []collector.ProcessInfo `json:"processes"`
}

// RuntimeSnapshot is the current host state used for verification (a fresh
// agent SystemInfo report or the latest stored host_system_info).
type RuntimeSnapshot struct {
	Services  []collector.ServiceInfo
	Processes []collector.ProcessInfo
}

// RuntimeVerifyResult is the outcome of one runtime verification.
type RuntimeVerifyResult struct {
	Status string `json:"status"` // passed | failed | na
	Detail string `json:"detail"`
}

// ParseRuntimeBaseline decodes the JSONB baseline stored on a patch task.
func ParseRuntimeBaseline(raw []byte) (RuntimeBaseline, error) {
	var b RuntimeBaseline
	if len(raw) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("parse runtime baseline: %w", err)
	}
	return b, nil
}

// EvaluateRuntimeVerification compares a baseline snapshot with a current
// system snapshot:
//   - services that were running must still be running (strict);
//   - processes in the baseline whose name matches the patched asset must
//     still exist under the same name (loose, PID may change).
//
// An empty baseline or a baseline with no applicable checks reports "na"
// (the agent never reported host telemetry before the patch).
func EvaluateRuntimeVerification(baseline RuntimeBaseline, current RuntimeSnapshot, assetName string) RuntimeVerifyResult {
	if len(baseline.Services) == 0 && len(baseline.Processes) == 0 {
		return RuntimeVerifyResult{Status: "na", Detail: "no runtime baseline available"}
	}

	currentServices := make(map[string]collector.ServiceInfo, len(current.Services))
	for _, svc := range current.Services {
		currentServices[svc.Name] = svc
	}
	currentProcesses := make(map[string]bool, len(current.Processes))
	for _, p := range current.Processes {
		currentProcesses[p.Name] = true
	}

	var failures []string
	applicable := 0
	for _, svc := range baseline.Services {
		if svc.State != "running" {
			continue
		}
		applicable++
		cur, ok := currentServices[svc.Name]
		if !ok || cur.State != "running" {
			failures = append(failures, fmt.Sprintf("service %q is not running", svc.Name))
		}
	}
	for _, p := range baseline.Processes {
		if p.Name != assetName {
			continue
		}
		applicable++
		if !currentProcesses[p.Name] {
			failures = append(failures, fmt.Sprintf("process %q is missing", p.Name))
		}
	}

	if applicable == 0 {
		return RuntimeVerifyResult{Status: "na", Detail: "no applicable runtime checks in baseline"}
	}
	if len(failures) == 0 {
		return RuntimeVerifyResult{Status: "passed", Detail: "runtime checks passed"}
	}
	return RuntimeVerifyResult{Status: "failed", Detail: strings.Join(failures, "; ")}
}
