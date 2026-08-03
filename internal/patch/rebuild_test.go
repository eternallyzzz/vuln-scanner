package patch

import "testing"

func TestBuildCommandRebuild(t *testing.T) {
	cfg := &Config{}
	// Colon and slash in the asset name must not matter: rebuild is advisory.
	cmd, err := BuildCommand(cfg, "rebuild", "rebuild image", "bitnami/kafka:latest", "")
	if err != nil {
		t.Fatalf("rebuild command errored: %v", err)
	}
	if cmd.Deployable {
		t.Error("rebuild command must not be deployable")
	}
	if len(cmd.ArgvLists) != 0 {
		t.Errorf("rebuild command must have no argv, got %v", cmd.ArgvLists)
	}
	if cmd.Display == "" {
		t.Error("rebuild command should carry an advisory message")
	}
}
