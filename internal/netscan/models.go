package netscan

// Service is one open TCP service with a best-effort banner fingerprint.
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Host is one discovered network host.
type Host struct {
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname,omitempty"`
	OSTypeGuess string    `json:"os_type"`
	Services    []Service `json:"services"`
}
