package report

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"fmt"
	"html/template"
	"time"
)

//go:embed report.html
var reportHTMLSource string

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
	"fmtDate": func(t time.Time) string { return t.Format("2006-01-02") },
	"fmtDatePtr": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format("2006-01-02")
	},
	"fmtPtrTime": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format("2006-01-02 15:04")
	},
	"fmtFloat": func(v float64) string { return fmt.Sprintf("%.2f", v) },
	"yesno": func(b bool) string {
		if b {
			return "是"
		}
		return "否"
	},
	"mapGet": func(m map[string]int, k string) int { return m[k] },
}).Parse(reportHTMLSource))

// RenderHTML renders the email body from the assembled report data.
func RenderHTML(d Data) (string, error) {
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// BuildCSV renders the active-risk detail attachment (up to the rows already
// gathered by Build), using the same columns as the risk export endpoint.
func BuildCSV(d Data) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"cve_id", "canonical_cve_id", "agent_id", "hostname", "asset_name",
		"severity", "risk_level", "cvss_score", "epss_score", "kev",
		"exposure_score", "asset_criticality", "risk_score", "eol",
		"eol_product", "detected_at", "due_at", "overdue", "fixed_version", "patch_url",
	})
	for _, r := range d.Risks {
		due := ""
		if r.DueAt != nil {
			due = r.DueAt.Format(time.RFC3339)
		}
		_ = w.Write([]string{
			r.CVEID,
			r.CanonicalCVEID,
			r.AgentID,
			r.Hostname,
			r.AssetName,
			r.Severity,
			r.RiskLevel,
			reportF2s(r.CVSSScore),
			reportF2s(r.EPSSScore),
			reportB2s(r.KEV),
			reportF2s(r.ExposureScore),
			reportF2s(r.AssetCriticality),
			reportF2s(r.RiskScore),
			reportB2s(r.EOL),
			r.EOLProduct,
			r.DetectedAt.Format(time.RFC3339),
			due,
			reportB2s(r.Overdue),
			r.FixedVersion,
			r.PatchURL,
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func reportF2s(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

func reportB2s(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
