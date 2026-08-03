package store

import (
	"context"
)

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
