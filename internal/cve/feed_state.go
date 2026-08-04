package cve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"vuln-scanner/internal/store"
)

const feedStatePrefix = "feed:"

// FeedState is the persisted cache metadata for one feed item (a source, a
// keyword, a package, or a single document URL).
type FeedState struct {
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	Cursor        string    `json:"cursor,omitempty"`
	LastRunAt     time.Time `json:"last_run_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	EntryCount    int       `json:"entry_count,omitempty"`
}

func feedStateKey(source, key string) string {
	return feedStatePrefix + source + ":" + key
}

// feedHash returns a stable hex key for long or user-controlled identifiers.
func feedHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func loadFeedState(ctx context.Context, st *store.Store, source, key string) (FeedState, error) {
	var s FeedState
	if st == nil {
		return s, nil
	}
	raw, err := st.GetMeta(ctx, feedStateKey(source, key))
	if err != nil || raw == "" {
		return s, err
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return FeedState{}, fmt.Errorf("decode feed state %s/%s: %w", source, key, err)
	}
	return s, nil
}

func saveFeedState(ctx context.Context, st *store.Store, source, key string, s FeedState) error {
	if st == nil {
		return nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode feed state %s/%s: %w", source, key, err)
	}
	return st.SetMeta(ctx, feedStateKey(source, key), string(raw))
}

func (s *FeedState) markRun() {
	s.LastRunAt = time.Now().UTC()
}

func (s *FeedState) markSuccess(count int) {
	now := time.Now().UTC()
	s.LastRunAt = now
	s.LastSuccessAt = now
	s.LastError = ""
	s.EntryCount = count
}

func (s *FeedState) markError(err error) {
	s.LastRunAt = time.Now().UTC()
	if err != nil {
		s.LastError = err.Error()
	}
}

func (s *FeedState) freshSince(interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	return !s.LastSuccessAt.IsZero() && time.Since(s.LastSuccessAt) < interval
}
