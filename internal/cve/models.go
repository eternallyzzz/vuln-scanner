package cve

import (
	"encoding/json"
	"fmt"
	"time"
)

type PackageInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Vulnerability struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Severity []CVSS     `json:"severity"`
	Affected []Affected `json:"affected"`
	Fixed    string     `json:"fixed"`
	Aliases  []string   `json:"aliases"`
	Modified time.Time  `json:"modified"`
}

type CVSS struct {
	Type  string      `json:"type"`
	Score interface{} `json:"score"`
}

type Affected struct {
	Package PackageInfo `json:"package"`
	Ranges  []Range     `json:"ranges"`
}

type Range struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type QueryRequestV1 struct {
	Version string      `json:"version,omitempty"`
	Package PackageInfo `json:"package"`
}

type QueryBatchRequest struct {
	Queries []QueryRequestV1 `json:"queries"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type AssetToMatch struct {
	Name      string
	Version   string
	Format    string
	Ecosystem string
}

type MatchedCVE struct {
	CVEID              string  `json:"cve_id"`
	AssetName          string  `json:"asset_name"`
	AssetVersion       string  `json:"asset_version"`
	FixedVersion       string  `json:"fixed_version,omitempty"`
	FixState           string  `json:"fix_state,omitempty"`
	KBArticle          string  `json:"kb_article,omitempty"`
	KBURL              string  `json:"kb_url,omitempty"`
	CpeVer             string  `json:"cpe_ver,omitempty"`
	OSProduct          bool    `json:"os_product,omitempty"`
	VerificationSource string  `json:"verification_source,omitempty"`
	Severity           string  `json:"severity"`
	CVSSScore          float64 `json:"cvss_score"`
	Summary            string  `json:"summary"`
	Source             string  `json:"source"`
	MatchStatus        string  `json:"match_status"`
}

type MSRCUpdate struct {
	ID                 string `json:"ID"`
	DocumentTitle      string `json:"DocumentTitle"`
	CvrfURL            string `json:"CvrfUrl"`
	InitialReleaseDate string `json:"InitialReleaseDate"`
}

type MSRCUpdatesResponse struct {
	Value    []MSRCUpdate `json:"value"`
	NextLink string       `json:"@odata.nextLink,omitempty"`
}

type ValueWrapper struct {
	Value string `json:"Value"`
}

func (v *ValueWrapper) UnmarshalJSON(data []byte) error {
	var wrapper struct {
		Val json.RawMessage `json:"Value"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		var raw interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		switch val := raw.(type) {
		case string:
			v.Value = val
		case float64:
			v.Value = fmt.Sprintf("%g", val)
		}
		return nil
	}
	var s string
	if json.Unmarshal(wrapper.Val, &s) == nil {
		v.Value = s
		return nil
	}
	var f float64
	if json.Unmarshal(wrapper.Val, &f) == nil {
		v.Value = fmt.Sprintf("%g", f)
		return nil
	}
	v.Value = string(wrapper.Val)
	return nil
}

type CVRFDocument struct {
	DocumentTitle ValueWrapper        `json:"DocumentTitle"`
	Vulnerability []CVRFVulnerability `json:"Vulnerability"`
	ProductTree   CVRFProductTree     `json:"ProductTree"`
}

type CVRFVulnerability struct {
	Title           ValueWrapper      `json:"Title"`
	CVE             string            `json:"CVE"`
	Notes           []CVRFNote        `json:"Notes"`
	CVSSScoreSets   []CVRFScoreSet    `json:"CVSSScoreSets"`
	Remediations    []CVRFRemediation `json:"Remediations"`
	ProductStatuses []CVRFStatus      `json:"ProductStatuses"`
	Threats         []CVRFThreat      `json:"Threats"`
}

type CVRFNote struct {
	Title string `json:"Title"`
	Type  int    `json:"Type"`
	Value string `json:"Value"`
}

type CVRFScoreSet struct {
	BaseScore ValueWrapper `json:"BaseScore"`
	Vector    string       `json:"Vector"`
}

type CVRFRemediation struct {
	Description ValueWrapper `json:"Description"`
	URL         string       `json:"URL"`
	ProductID   []string     `json:"ProductID"`
	Type        int          `json:"Type"`
	FixedBuild  string       `json:"FixedBuild"`
}

type CVRFStatus struct {
	ProductID []string `json:"ProductID"`
	Type      int      `json:"Type"`
}

type CVRFThreat struct {
	Description ValueWrapper `json:"Description"`
	ProductID   []string     `json:"ProductID"`
	Type        int          `json:"Type"`
}

type CVRFProductTree struct {
	Branch          []CVRFBranch          `json:"Branch"`
	FullProductName []CVRFFullProductName `json:"FullProductName"`
}

type CVRFFullProductName struct {
	ProductID string `json:"ProductID"`
	CPE       string `json:"CPE"`
	Value     string `json:"Value"`
}

type CVRFBranch struct {
	Name  string     `json:"Name"`
	Items []CVRFItem `json:"Items"`
}

type CVRFItem struct {
	ProductID string     `json:"ProductID"`
	Value     string     `json:"Value"`
	Items     []CVRFItem `json:"Items"`
	Type      int        `json:"Type"`
}

type NVDResponse struct {
	Vulnerabilities []NVDVuln `json:"vulnerabilities"`
	ResultsPerPage  int       `json:"resultsPerPage"`
	TotalResults    int       `json:"totalResults"`
}

type NVDVuln struct {
	CVE NVDCVE `json:"cve"`
}

type NVDCVE struct {
	ID             string           `json:"id"`
	Published      string           `json:"published"`
	Descriptions   []NVDDescription `json:"descriptions"`
	Metrics        NVDMetrics       `json:"metrics"`
	Configurations json.RawMessage  `json:"configurations"`
}

type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDMetrics struct {
	CVSSMetricV31 []NVDCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []NVDCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []NVDCVSSMetric `json:"cvssMetricV2"`
}

type NVDCVSSMetric struct {
	CVSSData NVDCVSSData `json:"cvssData"`
}

type NVDCVSSData struct {
	BaseScore float64 `json:"baseScore"`
	Severity  string  `json:"baseSeverity"`
}

type NVDConfigurations struct {
	Nodes []NVDNode `json:"nodes"`
}

type NVDNode struct {
	Operator string   `json:"operator"`
	CPEMatch []NVDCPE `json:"cpeMatch"`
}

type NVDCPE struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

func EcosystemForFormat(format string) string {
	switch format {
	case "deb":
		return "Debian"
	case "rpm":
		return "Red Hat"
	case "apk":
		return "Alpine"
	case "snap":
		return "Snap"
	case "win":
		return ""
	case "appx":
		return ""
	case "hotfix":
		return ""
	case "os":
		return ""
	case "pypi":
		return "PyPI"
	case "npm":
		return "npm"
	case "go-mod":
		return "Go"
	case "maven":
		return "Maven"
	case "rust":
		return "crates.io"
	case "dotnet":
		return "NuGet"
	case "php":
		return "Packagist"
	case "java":
		return "Maven"
	case "go":
		return "Go"
	default:
		return "OSS-Fuzz"
	}
}

func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func SeverityFromMSRC(value string) string {
	switch value {
	case "Critical":
		return "CRITICAL"
	case "Important":
		return "HIGH"
	case "Moderate":
		return "MEDIUM"
	case "Low":
		return "LOW"
	}
	return "MEDIUM"
}
