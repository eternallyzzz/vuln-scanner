package cve

import (
	"errors"
	"testing"
	"time"
)

func TestFeedHashStableAndDistinct(t *testing.T) {
	a := feedHash("openssl", "Debian")
	if a != feedHash("openssl", "Debian") {
		t.Fatal("feedHash must be deterministic")
	}
	if a == feedHash("openssl") {
		t.Fatal("feedHash must distinguish different part counts")
	}
}

func TestFeedStateMarkers(t *testing.T) {
	var s FeedState
	s.markSuccess(42)
	if s.LastSuccessAt.IsZero() || s.EntryCount != 42 || s.LastError != "" {
		t.Fatalf("markSuccess wrote wrong state: %+v", s)
	}
	s.markError(errors.New("boom"))
	if s.LastError != "boom" {
		t.Fatalf("markError wrote wrong error: %+v", s)
	}
	if s.LastSuccessAt.IsZero() {
		t.Fatal("markError must preserve the last successful refresh")
	}
}

func TestFeedStateFreshSince(t *testing.T) {
	var s FeedState
	if s.freshSince(0) {
		t.Fatal("empty state must not be fresh")
	}
	s.markSuccess(1)
	if !s.freshSince(24 * time.Hour) {
		t.Fatal("fresh state must report fresh within interval")
	}
}
