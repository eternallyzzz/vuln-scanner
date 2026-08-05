package cve

import (
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -update regenerates testdata/accuracy/snapshot.json from the current
// fixtures. Fixture "expected" lists remain the ground truth and are always
// checked, so -update cannot mask a fixture regression.
var updateAccuracySnapshot = flag.Bool("update", false, "regenerate testdata/accuracy/snapshot.json")

type accuracySnapshot struct {
	Fixtures  []accuracyFixtureSnapshot `json:"fixtures"`
	Aggregate accuracyMetrics           `json:"aggregate"`
}

type accuracyFixtureSnapshot struct {
	Name     string            `json:"name"`
	Metrics  accuracyMetrics   `json:"metrics"`
	Verdicts []accuracyVerdict `json:"verdicts"`
}

func TestAccuracySnapshot(t *testing.T) {
	fixtures := loadAccuracyFixtures(t)
	snap := accuracySnapshot{Fixtures: make([]accuracyFixtureSnapshot, 0, len(fixtures))}
	for _, fx := range fixtures {
		produced, err := evaluateAccuracyFixture(fx)
		if err != nil {
			t.Fatalf("fixture %s: %v", fx.Name, err)
		}
		expected := normalizedVerdicts(fx.Expected)
		if diff := diffVerdicts(produced, expected); len(diff) > 0 {
			t.Errorf("fixture %s: produced != expected:\n%s", fx.Name, strings.Join(diff, "\n"))
		}
		snap.Fixtures = append(snap.Fixtures, accuracyFixtureSnapshot{
			Name:     fx.Name,
			Metrics:  compareVerdicts(produced, expected),
			Verdicts: produced,
		})
	}
	snap.Aggregate = aggregateMetrics(snap.Fixtures)

	path := filepath.Join("testdata", "accuracy", "snapshot.json")
	if *updateAccuracySnapshot {
		writeSnapshot(t, path, snap)
		return
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("snapshot.json is local-only; run with -update to regenerate")
	}
	if err != nil {
		t.Fatalf("read snapshot (run with -update to create): %v", err)
	}
	var want accuracySnapshot
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if got := mustJSON(snap); got != strings.TrimSpace(string(b)) {
		t.Fatalf("snapshot drift:\n got: %s\nwant: %s", got, strings.TrimSpace(string(b)))
	}
}

func writeSnapshot(t *testing.T, path string, snap accuracySnapshot) {
	t.Helper()
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}
