package cve

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type CacheEntry struct {
	CVEIDs   []string  `json:"cve_ids"`
	CachedAt time.Time `json:"cached_at"`
}

type Cache struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewCache(dbPath string) (*Cache, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS vuln_cache (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			cached_at INTEGER NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &Cache{db: db}, nil
}

func (c *Cache) Close() error {
	return c.db.Close()
}

func (c *Cache) keyStr(name, version, format string) string {
	data := fmt.Sprintf("%s:%s:%s", name, version, format)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:])
}

func (c *Cache) Get(name, version, format string) (*CacheEntry, bool) {
	key := c.keyStr(name, version, format)

	c.mu.RLock()
	defer c.mu.RUnlock()

	var raw []byte
	var cachedAt int64
	err := c.db.QueryRow("SELECT value, cached_at FROM vuln_cache WHERE key=?", key).
		Scan(&raw, &cachedAt)
	if err != nil {
		return nil, false
	}

	if time.Now().Unix()-cachedAt > int64(24*time.Hour.Seconds()) {
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, false
	}

	return &entry, true
}

func (c *Cache) Set(name, version, format string, entry *CacheEntry) error {
	key := c.keyStr(name, version, format)
	entry.CachedAt = time.Now()

	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	_, err = c.db.Exec(
		"INSERT OR REPLACE INTO vuln_cache (key, value, cached_at) VALUES (?, ?, ?)",
		key, raw, time.Now().Unix(),
	)
	return err
}

func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.Exec("DELETE FROM vuln_cache")
	return err
}
