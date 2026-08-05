package store

import (
	"context"
)

// TranslationRule is one row of package_translations: a regexp pattern that
// maps an installed package name to a canonical product/CPE name, with
// optional vendor matching, embedded-version extraction and a hotfix KB.
type TranslationRule struct {
	Pattern        string
	VendorPattern  string
	VersionPattern string
	HotfixKB       string
	Product        string
	Platform       string
	Priority       int
}

// LoadTranslationRules returns all package translation rules ordered by
// priority (highest first) and insertion order. Matching happens in Go so the
// rules can be unit tested without a database.
func (s *Store) LoadTranslationRules(ctx context.Context) ([]TranslationRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT pattern, vendor_pattern, version_pattern, hotfix_kb, cpe_name, platform, priority
		FROM package_translations
		ORDER BY priority DESC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []TranslationRule
	for rows.Next() {
		var r TranslationRule
		if err := rows.Scan(&r.Pattern, &r.VendorPattern, &r.VersionPattern,
			&r.HotfixKB, &r.Product, &r.Platform, &r.Priority); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) TranslatePackage(ctx context.Context, name string, platform string) (string, error) {
	var cpeName string
	err := s.pool.QueryRow(ctx, `
		SELECT cpe_name FROM package_translations
		WHERE (platform = $1 OR platform = 'any')
		AND $2 ~ pattern
		ORDER BY priority DESC, id ASC
		LIMIT 1
	`, platform, name).Scan(&cpeName)
	if err != nil {
		return "", err
	}
	return cpeName, nil
}
