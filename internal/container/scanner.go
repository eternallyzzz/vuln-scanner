package container

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Image struct {
	Repository string `json:"Repository"`
	Tag        string `json:"Tag"`
	Digest     string `json:"Digest"`
	ID         string `json:"ID"`
}

func (i Image) Ref() string {
	if i.Tag != "" && i.Tag != "<none>" {
		return i.Repository + ":" + i.Tag
	}
	if i.Digest != "" && i.Digest != "<none>" {
		return i.Repository + "@" + i.Digest
	}
	return i.Repository
}

func (i Image) Version() string {
	if i.Digest != "" && i.Digest != "<none>" {
		return i.Digest
	}
	if i.ID != "" {
		return i.ID
	}
	return i.Tag
}

type Finding struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	CVSSScore        float64
	Title            string
}

type Scanner struct {
	DockerHost  string
	TrivyImage  string
	CacheVolume string
	Timeout     time.Duration
}

func NewScanner(cfg *Config) *Scanner {
	return &Scanner{
		DockerHost:  cfg.DockerHost,
		TrivyImage:  cfg.TrivyImage,
		CacheVolume: cfg.TrivyCacheVolume,
		Timeout:     cfg.ResolvedTimeout(),
	}
}

func (s *Scanner) dockerSocketPath() string {
	if strings.HasPrefix(s.DockerHost, "unix://") {
		return strings.TrimPrefix(s.DockerHost, "unix://")
	}
	if strings.HasPrefix(s.DockerHost, "npipe://") {
		return s.DockerHost
	}
	return s.DockerHost
}

// ListImages enumerates local images via `docker images --digests --format json`.
func (s *Scanner) ListImages(ctx context.Context) ([]Image, error) {
	cmd := exec.CommandContext(ctx, "docker", "--host", s.DockerHost,
		"images", "--digests", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker images: %w", err)
	}
	return parseDockerImagesLines(string(out))
}

func parseDockerImagesLines(data string) ([]Image, error) {
	var images []Image
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var img Image
		if err := json.Unmarshal([]byte(line), &img); err != nil {
			continue
		}
		if img.Repository != "" && img.Repository != "<none>" {
			images = append(images, img)
		}
	}
	return images, sc.Err()
}

// ScanImage runs Trivy in a container against the given image ref and returns
// vulnerability findings.
func (s *Scanner) ScanImage(ctx context.Context, ref string) ([]Finding, error) {
	args := []string{
		"run", "--rm",
		"-v", s.dockerSocketPath() + ":/var/run/docker.sock",
		"-v", s.CacheVolume + ":/root/.cache",
		s.TrivyImage,
		"image", "--format", "json", "--no-progress",
		"--timeout", s.Timeout.String(),
		ref,
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy scan %s: %s", ref, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("trivy scan %s: %w", ref, err)
	}
	return parseTrivyReport(out)
}

type trivyReport struct {
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
			Title string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivyReport(data []byte) ([]Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	var out []Finding
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := strings.ToUpper(v.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			out = append(out, Finding{
				VulnerabilityID:  v.VulnerabilityID,
				PkgName:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         sev,
				CVSSScore:        maxCVSS(v.CVSS),
				Title:            truncateTitle(v.Title),
			})
		}
	}
	return out, nil
}

func maxCVSS(sources map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) float64 {
	var max float64
	for _, s := range sources {
		if s.V3Score > max {
			max = s.V3Score
		}
		if s.V2Score > max {
			max = s.V2Score
		}
	}
	return max
}

func truncateTitle(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "..."
}

// FilterImages applies the configured allowlist, exclude patterns, regex
// filter and max-image cap.
func FilterImages(images []Image, cfg *Config) []Image {
	if cfg == nil {
		return images
	}
	allow := map[string]bool{}
	for _, a := range cfg.Images {
		allow[strings.ToLower(a)] = true
	}
	var filterRe *regexp.Regexp
	if cfg.ImageFilter != "" {
		filterRe = regexp.MustCompile(cfg.ImageFilter)
	}
	var out []Image
	for _, img := range images {
		ref := img.Ref()
		lower := strings.ToLower(ref)
		if len(allow) > 0 && !allow[lower] && !allow[strings.ToLower(img.Repository)] {
			continue
		}
		excluded := false
		for _, ex := range cfg.Exclude {
			if ex != "" && strings.Contains(lower, strings.ToLower(ex)) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if filterRe != nil && !filterRe.MatchString(ref) {
			continue
		}
		out = append(out, img)
		if cfg.MaxImages > 0 && len(out) >= cfg.MaxImages {
			break
		}
	}
	return out
}
