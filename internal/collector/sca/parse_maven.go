package sca

import (
	"encoding/xml"
	"os"
	"strings"

	"vuln-scanner/internal/collector"
)

func parseMaven(path string) []collector.Asset {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var proj struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Parent     *struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"parent"`
		Deps struct {
			Dep []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	}
	if err := xml.NewDecoder(f).Decode(&proj); err != nil {
		return nil
	}

	var assets []collector.Asset

	groupId := proj.GroupID
	version := proj.Version
	if proj.Parent != nil {
		if groupId == "" {
			groupId = proj.Parent.GroupID
		}
		if version == "" {
			version = proj.Parent.Version
		}
	}

	if proj.ArtifactID != "" {
		assets = append(assets, collector.Asset{
			Name:    proj.ArtifactID,
			Version: dedupeVersion(version),
			Format:  "maven",
			Vendor:  strings.TrimSpace(groupId),
		})
	}

	for _, d := range proj.Deps.Dep {
		if d.ArtifactID == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    strings.TrimSpace(d.ArtifactID),
			Version: dedupeVersion(d.Version),
			Format:  "maven",
			Vendor:  strings.TrimSpace(d.GroupID),
		})
	}
	return assets
}
