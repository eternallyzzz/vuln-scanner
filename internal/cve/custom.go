package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"vuln-scanner/internal/store"
)

// SyncCustomIntel mirrors enabled built-in intel rules into cve_feed under
// source='custom' so they participate in the existing name/version matching
// pipeline. The mirror is fully rebuilt on every startup (idempotent).
func (f *FeedManager) SyncCustomIntel(ctx context.Context, st *store.Store) error {
	rows, err := st.EnabledCustomIntel(ctx)
	if err != nil {
		return fmt.Errorf("list custom intel: %w", err)
	}
	if err := f.DeleteAllBySource(ctx, "custom"); err != nil {
		return fmt.Errorf("clear custom intel mirror: %w", err)
	}
	entries := customIntelFeedEntries(rows)
	if len(entries) == 0 {
		return nil
	}
	if err := f.BatchUpsert(ctx, entries); err != nil {
		return fmt.Errorf("upsert custom intel mirror: %w", err)
	}
	slog.Info("custom intel mirrored", "rules", len(entries))
	return nil
}

// SyncCustomIntel mirrors enabled built-in intel rules into cve_feed. It is
// invoked by the lease-holding feed loop so concurrent instances never race
// the full mirror rebuild.
func (l *Loader) SyncCustomIntel(ctx context.Context) error {
	if l.feed == nil || l.store == nil {
		return nil
	}
	return l.feed.SyncCustomIntel(ctx, l.store)
}

// customIntelFeedEntries converts enabled rules to feed rows. Rules with
// invalid affected payloads are skipped with a warning instead of blocking
// startup.
func customIntelFeedEntries(rows []store.CustomIntel) []*FeedEntry {
	var entries []*FeedEntry
	for i := range rows {
		r := rows[i]
		affected, err := normalizeCustomAffected(r.Affected)
		if err != nil {
			slog.Warn("custom intel rule skipped: invalid affected",
				"intel_id", r.IntelID, "error", err)
			continue
		}
		entries = append(entries, &FeedEntry{
			Source:      "custom",
			SourceKey:   fmt.Sprintf("intel-%d", r.ID),
			CVEID:       r.IntelID,
			CVEURL:      r.AdvisoryURL,
			Affected:    affected,
			Severity:    r.Severity,
			CVSSScore:   r.CVSSScore,
			Summary:     r.Summary,
			PublishedAt: time.Now(),
			FetchedAt:   time.Now(),
		})
	}
	return entries
}

// normalizeCustomAffected validates the affected array shape shared with the
// public feeds and returns a canonical JSON representation.
func normalizeCustomAffected(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("affected is required")
	}
	var products []AffectedProduct
	if err := json.Unmarshal(raw, &products); err != nil {
		return nil, fmt.Errorf("invalid affected: %w", err)
	}
	if len(products) == 0 {
		return nil, fmt.Errorf("affected must contain at least one product")
	}
	for _, p := range products {
		if p.Name == "" {
			return nil, fmt.Errorf("affected product name is required")
		}
	}
	out, err := json.Marshal(products)
	if err != nil {
		return nil, err
	}
	return out, nil
}
