package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// KBMetadata is the verified link metadata for one Microsoft KB article.
type KBMetadata struct {
	KB                 string     `json:"kb"`
	Title              string     `json:"title"`
	ProductFamily      string     `json:"product_family"`
	SupportURL         string     `json:"support_url"`
	CatalogURL         string     `json:"catalog_url"`
	DownloadURL        string     `json:"download_url"`
	DownloadSHA256     string     `json:"download_sha256,omitempty"`
	DownloadResolvedAt *time.Time `json:"download_resolved_at,omitempty"`
	Status             string     `json:"status"` // unknown|ok|broken
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM feed_meta WHERE key=$1`, key).Scan(&value)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_meta (key, value, updated_at) VALUES ($1,$2,now())
		ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()
	`, key, value)
	return err
}

// DeleteMetaPrefix removes all feed_meta rows whose key starts with prefix.
// It is used to invalidate cached feed state when a parser version changes.
func (s *Store) DeleteMetaPrefix(ctx context.Context, prefix string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM feed_meta WHERE key LIKE $1 || '%'`, prefix)
	return err
}

// UpsertKBMetadata records or refreshes link metadata for a KB. The
// verification status is only set on first insert; later syncs must not
// reset a verified/broken result.
func (s *Store) UpsertKBMetadata(ctx context.Context, m KBMetadata) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO kb_metadata (kb, title, product_family, support_url, catalog_url, download_url, status, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,'unknown',now())
		ON CONFLICT (kb) DO UPDATE SET
			title=EXCLUDED.title,
			product_family=EXCLUDED.product_family,
			support_url=EXCLUDED.support_url,
			catalog_url=EXCLUDED.catalog_url,
			updated_at=now()
	`, m.KB, m.Title, m.ProductFamily, m.SupportURL, m.CatalogURL, m.DownloadURL)
	return err
}

func (s *Store) UpdateKBMetadataStatus(ctx context.Context, kb, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE kb_metadata SET status=$2, verified_at=now(), updated_at=now() WHERE kb=$1
	`, kb, status)
	return err
}

// SetKBDownloadInfo records the resolved direct .msu download for a KB.
func (s *Store) SetKBDownloadInfo(ctx context.Context, kb, downloadURL, sha256 string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE kb_metadata
		SET download_url=$2, download_sha256=$3, download_resolved_at=now(), updated_at=now()
		WHERE kb=$1
	`, kb, downloadURL, sha256)
	return err
}

func (s *Store) GetKBMetadataMap(ctx context.Context, kbs []string) (map[string]KBMetadata, error) {
	out := make(map[string]KBMetadata, len(kbs))
	if len(kbs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT kb, title, product_family, support_url, catalog_url, download_url,
			download_sha256, download_resolved_at, status, verified_at, updated_at
		FROM kb_metadata WHERE kb = ANY($1)
	`, kbs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m KBMetadata
		if err := rows.Scan(&m.KB, &m.Title, &m.ProductFamily, &m.SupportURL,
			&m.CatalogURL, &m.DownloadURL, &m.DownloadSHA256, &m.DownloadResolvedAt,
			&m.Status, &m.VerifiedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out[m.KB] = m
	}
	return out, rows.Err()
}

// ListKBMetadataForValidation returns KBs whose support links still need a
// HEAD check (never verified, broken, or last verified more than 7 days ago).
func (s *Store) ListKBMetadataForValidation(ctx context.Context, limit int) ([]KBMetadata, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kb, title, product_family, support_url, catalog_url, download_url,
			download_sha256, download_resolved_at, status, verified_at, updated_at
		FROM kb_metadata
		WHERE support_url <> ''
		ORDER BY
			CASE WHEN verified_at IS NULL THEN 0 ELSE 1 END,
			verified_at ASC NULLS FIRST
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBMetadata
	for rows.Next() {
		var m KBMetadata
		if err := rows.Scan(&m.KB, &m.Title, &m.ProductFamily, &m.SupportURL,
			&m.CatalogURL, &m.DownloadURL, &m.DownloadSHA256, &m.DownloadResolvedAt,
			&m.Status, &m.VerifiedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ActiveKBArticles returns the distinct KB articles currently referenced by
// active vulnerability results; their links matter most to users.
func (s *Store) ActiveKBArticles(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT kb_article FROM cve_results
		WHERE status='active' AND kb_article LIKE 'KB%'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kb string
		if err := rows.Scan(&kb); err != nil {
			return nil, err
		}
		out = append(out, kb)
	}
	return out, rows.Err()
}
