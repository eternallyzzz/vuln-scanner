package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"vuln-scanner/internal/store"
)

var (
	errInvalidKBArticle  = errors.New("kb must look like KB1234567")
	errInvalidKBArch     = errors.New("arch must be empty, x64 or arm64")
	errInvalidKBOSFamily = errors.New("os_family must be empty, windows 10, windows 11 or server")
	errInvalidKBURL      = errors.New("url must be an absolute http(s) URL")
	errInvalidKBSHA256   = errors.New("sha256 must be empty or a 64-char hex string")
)

var kbArticleRe = regexp.MustCompile(`^KB[0-9]+$`)
var sha256HexRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type kbDownloadImport struct {
	KB       string `json:"kb"`
	OSFamily string `json:"os_family"`
	Arch     string `json:"arch"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

// normalizeKBDownloadImport validates and normalizes one operator-supplied
// KB download row. The URL host is intentionally not restricted here: the
// deployability allowlist in BuildCommandForAgent remains the single gate
// for auto-deployment, so an operator may record a manual-download link that
// is not auto-deployable.
func normalizeKBDownloadImport(in kbDownloadImport) (store.KBDownload, error) {
	kb := strings.TrimSpace(in.KB)
	if !kbArticleRe.MatchString(kb) {
		return store.KBDownload{}, errInvalidKBArticle
	}
	arch := strings.ToLower(strings.TrimSpace(in.Arch))
	if arch == "amd64" {
		arch = "x64"
	}
	if arch != "" && arch != "x64" && arch != "arm64" {
		return store.KBDownload{}, errInvalidKBArch
	}
	family := strings.ToLower(strings.TrimSpace(in.OSFamily))
	if family != "" && family != "windows 10" && family != "windows 11" && family != "server" {
		return store.KBDownload{}, errInvalidKBOSFamily
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return store.KBDownload{}, errInvalidKBURL
	}
	sha := strings.TrimSpace(in.SHA256)
	if sha != "" && !sha256HexRe.MatchString(sha) {
		return store.KBDownload{}, errInvalidKBSHA256
	}
	return store.KBDownload{
		KB:       kb,
		OSFamily: family,
		Arch:     arch,
		Title:    strings.TrimSpace(in.Title),
		URL:      u.String(),
		SHA256:   strings.ToLower(sha),
	}, nil
}

// importKBDownloads accepts an operator-maintained batch of verified KB
// direct downloads. This is the manual fallback alongside the background
// Update Catalog resolver; both write to kb_downloads.
func (s *RESTServer) importKBDownloads(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Downloads []kbDownloadImport `json:"downloads"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, 400, "invalid JSON body")
			return
		}
	}
	if len(in.Downloads) == 0 {
		writeError(w, 400, "downloads must not be empty")
		return
	}
	if len(in.Downloads) > 500 {
		writeError(w, 400, "at most 500 downloads per import")
		return
	}

	var valid []store.KBDownload
	var errs []string
	for i, d := range in.Downloads {
		norm, err := normalizeKBDownloadImport(d)
		if err != nil {
			errs = append(errs, "row "+strconv.Itoa(i+1)+": "+err.Error())
			continue
		}
		valid = append(valid, norm)
	}
	if len(errs) > 0 {
		writeError(w, 400, strings.Join(errs, "; "))
		return
	}
	for _, d := range valid {
		if err := s.store.SetKBDownload(r.Context(), d); err != nil {
			writeError(w, 500, "persist download failed: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"imported":  len(valid),
		"downloads": valid,
	})
}
