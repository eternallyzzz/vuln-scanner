package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

func loadOpenAPIDoc(t *testing.T) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	if _, ok := doc["openapi"]; !ok {
		t.Fatal("openapi version missing")
	}
	if _, ok := doc["info"]; !ok {
		t.Fatal("info missing")
	}
	if _, ok := doc["paths"]; !ok {
		t.Fatal("paths missing")
	}
	if _, ok := doc["components"]; !ok {
		t.Fatal("components missing")
	}
	return doc
}

// TestOpenAPIRoutesCovered walks the real chi router and compares it
// bidirectionally with the documented paths, so route changes fail the test
// until the spec is updated.
func TestOpenAPIRoutesCovered(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	router, ok := s.Handler().(chi.Routes)
	if !ok {
		t.Fatal("REST handler must implement chi.Routes")
	}
	actual := map[string]bool{}
	if err := chi.Walk(router, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		actual[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(actual) == 0 {
		t.Fatal("no routes discovered")
	}

	doc := loadOpenAPIDoc(t)
	documented := map[string]bool{}
	paths, _ := doc["paths"].(map[string]interface{})
	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]interface{})
		if !ok {
			continue
		}
		for method := range item {
			if method == "parameters" {
				continue
			}
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	for key := range actual {
		if !documented[key] {
			t.Errorf("route exists in router but not in openapi.yaml: %s", key)
		}
	}
	for key := range documented {
		if !actual[key] {
			t.Errorf("route documented but not registered: %s", key)
		}
	}
}

// TestOpenAPIStructure validates the minimal per-operation contract: every
// operation has summary and responses; non-public operations carry x-roles.
func TestOpenAPIStructure(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	paths, _ := doc["paths"].(map[string]interface{})
	if len(paths) == 0 {
		t.Fatal("no paths documented")
	}
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]interface{})
		for method, rawOp := range item {
			if method == "parameters" {
				continue
			}
			op, ok := rawOp.(map[string]interface{})
			if !ok {
				t.Fatalf("%s %s: operation must be a mapping", method, path)
			}
			if _, ok := op["summary"]; !ok {
				t.Errorf("%s %s: summary missing", method, path)
			}
			if _, ok := op["responses"]; !ok {
				t.Errorf("%s %s: responses missing", method, path)
			}
			public := false
			if sec, ok := op["security"]; ok {
				if arr, ok := sec.([]interface{}); ok && len(arr) == 0 {
					public = true
				}
			}
			if !public {
				roles, ok := op["x-roles"].([]interface{})
				if !ok || len(roles) == 0 {
					t.Errorf("%s %s: x-roles missing for non-public operation", method, path)
				}
			}
		}
	}
}

// TestServeOpenAPI verifies the endpoint is public (no API key needed) and
// returns the embedded spec byte-for-byte.
func TestServeOpenAPI(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /openapi.yaml = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content-type = %q, want application/yaml", ct)
	}
	if !bytes.Equal(rr.Body.Bytes(), openAPISpec) {
		t.Fatal("served body differs from embedded spec")
	}
}
