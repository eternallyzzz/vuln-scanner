package store

import (
	"reflect"
	"testing"
)

func TestNetworkAgentIDStable(t *testing.T) {
	a := NetworkAgentID("192.168.1.10")
	b := NetworkAgentID("192.168.1.10")
	if a != b || len(a) != len("agent-net-")+12 || !hasPrefix(a, "agent-net-") {
		t.Fatalf("NetworkAgentID = %q, want stable agent-net-<hash>", a)
	}
	if NetworkAgentID("192.168.1.10") == NetworkAgentID("192.168.1.11") {
		t.Fatal("different IPs must map to different agent ids")
	}
}

func TestPortsRoundtrip(t *testing.T) {
	in := []int32{22, 80, 443}
	raw := formatPorts(in)
	got := parsePorts(raw)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("parsePorts(formatPorts(%v)) = %v", in, got)
	}
	if got := parsePorts("22, ,abc,70000,80"); !reflect.DeepEqual(got, []int32{22, 80}) {
		t.Fatalf("parsePorts invalid entries = %v", got)
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
