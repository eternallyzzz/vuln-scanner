package webdbscan

// Credential carries optional Basic-Auth or database credentials. Secrets
// never appear in scan results or audit entries.
type Credential struct {
	Username string
	Password string
}

// Product is one identified application/database product with a best-effort
// version and the evidence it was detected from.
type Product struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// WebResult is one HTTP(S) application fingerprint.
type WebResult struct {
	URL        string    `json:"url"`
	StatusCode int       `json:"status_code"`
	Title      string    `json:"title,omitempty"`
	Server     string    `json:"server,omitempty"`
	XPoweredBy string    `json:"x_powered_by,omitempty"`
	Generator  string    `json:"generator,omitempty"`
	Redirects  int       `json:"redirects,omitempty"`
	Products   []Product `json:"products"`
}

// DBResult is one database service probe.
type DBResult struct {
	DBType       string    `json:"db_type"`
	Version      string    `json:"version,omitempty"`
	AuthRequired bool      `json:"auth_required,omitempty"`
	Products     []Product `json:"products"`
}
