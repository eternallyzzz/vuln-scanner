package container

import (
	"testing"
)

const trivyFixture = `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx:latest",
  "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
  "Results": [
    {
      "Target": "nginx:latest (debian 12.10)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-1001",
          "PkgName": "libc6",
          "InstalledVersion": "2.36-9",
          "FixedVersion": "2.36-10",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {"V3Score": 8.1},
            "redhat": {"V3Score": 9.0, "V2Score": 7.0}
          },
          "Title": "a long title that is fine"
        },
        {
          "VulnerabilityID": "CVE-2026-1002",
          "PkgName": "libc6",
          "InstalledVersion": "2.36-9",
          "Severity": "unknown",
          "CVSS": {},
          "Title": ""
        },
        {
          "VulnerabilityID": "CVE-2026-1001",
          "PkgName": "libc6",
          "InstalledVersion": "2.36-9",
          "Severity": "HIGH",
          "Title": "duplicate should be dropped"
        }
      ]
    }
  ]
}`

func TestParseTrivyReport(t *testing.T) {
	findings, err := parseTrivyReport([]byte(trivyFixture))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (duplicate dropped)", len(findings))
	}
	if findings[0].Severity != "HIGH" || findings[0].CVSSScore != 9.0 {
		t.Errorf("first finding = %+v, want severity HIGH cvss 9.0", findings[0])
	}
	if findings[0].FixedVersion != "2.36-10" {
		t.Errorf("fixed version = %q", findings[0].FixedVersion)
	}
	if findings[1].Severity != "UNKNOWN" || findings[1].CVSSScore != 0 {
		t.Errorf("second finding = %+v, want UNKNOWN/0", findings[1])
	}
}

func TestParseDockerImagesLines(t *testing.T) {
	data := `{"Containers":"-1","CreatedAt":"2026-01-01 00:00:00","Digest":"sha256:abc","ID":"deadbeef","Repository":"nginx","SharedSize":"0","Size":"141MB","Tag":"latest"}
{"Containers":"0","CreatedAt":"2026-01-02 00:00:00","Digest":"<none>","ID":"cafe","Repository":"redis","SharedSize":"1","Size":"113MB","Tag":"7.2"}
{"Containers":"0","CreatedAt":"2026-01-02 00:00:00","Digest":"<none>","ID":"<missing>","Repository":"<none>","SharedSize":"1","Size":"1MB","Tag":"<none>"}`
	images, err := parseDockerImagesLines(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("images = %d, want 2 (dangling image dropped)", len(images))
	}
	if images[0].Ref() != "nginx:latest" || images[0].Version() != "sha256:abc" {
		t.Errorf("nginx = %+v", images[0])
	}
	if images[1].Ref() != "redis:7.2" || images[1].Version() != "cafe" {
		t.Errorf("redis = %+v", images[1])
	}
}

func TestFilterImages(t *testing.T) {
	images := []Image{
		{Repository: "nginx", Tag: "latest"},
		{Repository: "redis", Tag: "7.2"},
		{Repository: "kicbase/stable", Tag: "v0.0.40"},
		{Repository: "postgres", Tag: "latest"},
	}
	cfg := &Config{
		Exclude:   []string{"kicbase"},
		MaxImages: 10,
	}
	got := FilterImages(images, cfg)
	if len(got) != 3 {
		t.Fatalf("exclude filter: got %d, want 3", len(got))
	}

	cfg.Images = []string{"nginx:latest", "postgres"}
	cfg.Exclude = nil
	got = FilterImages(images, cfg)
	if len(got) != 2 || got[0].Ref() != "nginx:latest" || got[1].Ref() != "postgres:latest" {
		t.Fatalf("allowlist filter: %+v", got)
	}

	cfg = &Config{ImageFilter: `^nginx`, MaxImages: 10}
	got = FilterImages(images, cfg)
	if len(got) != 1 || got[0].Repository != "nginx" {
		t.Fatalf("regex filter: %+v", got)
	}

	cfg = &Config{MaxImages: 2}
	got = FilterImages(images, cfg)
	if len(got) != 2 {
		t.Fatalf("max cap: got %d, want 2", len(got))
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	if cfg.DockerHost != "unix:///var/run/docker.sock" || cfg.AgentID != "agent-container-docker" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	cfg.ScanIntervalMinutes = 5
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for interval < 15")
	}
	cfg.ScanIntervalMinutes = 60
	cfg.ImageFilter = "("
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid regex")
	}
}
