package store

import "testing"

func TestWebAgentIDStable(t *testing.T) {
	a := WebAgentID("web", "http://app.example.com")
	b := WebAgentID("web", "http://app.example.com")
	if a != b || len(a) != len("agent-web-")+12 {
		t.Fatalf("WebAgentID = %q, want stable agent-web-<hash>", a)
	}
	d := WebAgentID("db", "10.0.0.1:5432")
	if len(d) != len("agent-db-")+12 {
		t.Fatalf("WebAgentID(db) = %q, want agent-db-<hash>", d)
	}
	if a == d {
		t.Fatal("web and db ids must differ")
	}
	if WebAgentID("web", "http://app.example.com") == WebAgentID("web", "http://other.example.com") {
		t.Fatal("different targets must map to different agent ids")
	}
}
