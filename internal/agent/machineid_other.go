//go:build !linux && !windows

package agent

func machineID() string {
	return ""
}
