package server

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openAPISpec []byte

// serveOpenAPI exposes the hand-maintained OpenAPI 3.0.3 specification as a
// public read-only endpoint so clients and automation can fetch the exact
// contract without reading the repository.
func (s *RESTServer) serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}
