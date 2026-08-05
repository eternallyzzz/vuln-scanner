// Package eol normalizes agent OS identities and evaluates end-of-life
// status against a lifecycle table. All logic is pure Go so it can be unit
// tested without a database.
package eol

import (
	"strings"
	"time"

	"vuln-scanner/internal/store"
)

// Status is one agent OS lifecycle verdict.
type Status struct {
	State       string     `json:"state"` // eol | unsupported | supported | unknown
	Product     string     `json:"product,omitempty"`
	Cycle       string     `json:"cycle,omitempty"`
	EOLDate     *time.Time `json:"eol_date,omitempty"`
	SupportDate *time.Time `json:"support_date,omitempty"`
	LTS         bool       `json:"lts,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

// NormalizeOS maps an agent os_type/os_version pair to a (product, cycle)
// key understood by the os_lifecycle table. Unknown platforms return empty
// values.
func NormalizeOS(osType, osVersion string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(osType))
	v := strings.ToLower(strings.TrimSpace(osVersion))

	switch {
	case strings.Contains(t, "windows server 2025"):
		return "windows-server", "2025"
	case strings.Contains(t, "windows server 2022"):
		return "windows-server", "2022"
	case strings.Contains(t, "windows server 2019"):
		return "windows-server", "2019"
	case strings.Contains(t, "windows server 2016"):
		return "windows-server", "2016"
	case strings.Contains(t, "windows server 2012 r2"):
		return "windows-server", "2012 r2"
	case strings.Contains(t, "windows server 2012"):
		return "windows-server", "2012"
	case strings.Contains(t, "windows 11"):
		return "windows", "11"
	case strings.Contains(t, "windows 10"):
		return "windows", "10"
	case strings.Contains(t, "windows 8.1"):
		return "windows", "8.1"
	case strings.Contains(t, "windows 7"):
		return "windows", "7"
	case strings.Contains(t, "ubuntu"):
		return "ubuntu", majorMinor(v)
	case strings.Contains(t, "debian"):
		return "debian", major(v)
	case strings.Contains(t, "centos") && strings.Contains(t, "stream"):
		return "centos-stream", major(v)
	case strings.Contains(t, "centos"):
		return "centos", major(v)
	case strings.Contains(t, "alma"):
		return "almalinux", major(v)
	case strings.Contains(t, "rocky"):
		return "rocky", major(v)
	case strings.Contains(t, "suse"):
		return "sles", major(v)
	case strings.Contains(t, "amazon linux"):
		return "amazon-linux", major(v)
	case strings.Contains(t, "fedora"):
		return "fedora", major(v)
	case strings.Contains(t, "red hat") || strings.Contains(t, "rhel"):
		return "rhel", major(v)
	case strings.Contains(t, "arch"):
		return "arch", "rolling"
	}
	return "", ""
}

// Evaluate matches a (product, cycle) against the lifecycle table. A row is
// eol once now is on/after eol_date; otherwise unsupported once the support
// date has passed; otherwise supported. No matching row means unknown.
func Evaluate(product, cycle string, rows []store.OSLifecycle, now time.Time) Status {
	for _, r := range rows {
		if !strings.EqualFold(r.Product, product) || !strings.EqualFold(r.Cycle, cycle) {
			continue
		}
		st := Status{
			Product:     r.Product,
			Cycle:       r.Cycle,
			EOLDate:     r.EOLDate,
			SupportDate: r.SupportDate,
			LTS:         r.LTS,
			Notes:       r.Notes,
		}
		switch {
		case r.EOLDate != nil && !now.Before(*r.EOLDate):
			st.State = "eol"
		case r.SupportDate != nil && !now.Before(*r.SupportDate):
			st.State = "unsupported"
		default:
			st.State = "supported"
		}
		return st
	}
	return Status{State: "unknown", Product: product, Cycle: cycle}
}

func major(v string) string {
	if v == "" {
		return ""
	}
	m, _, _ := strings.Cut(v, ".")
	return m
}

func majorMinor(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}
