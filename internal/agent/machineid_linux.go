package agent

import (
	"os"
	"strings"
)

func machineID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		data, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return ""
		}
	}
	return strings.TrimSpace(string(data))
}
