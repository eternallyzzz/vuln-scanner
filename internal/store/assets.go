package store

import (
	"context"
	"time"
)

func (s *Store) UpsertAssetSnapshot(ctx context.Context, snap *AssetSnapshot) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO asset_snapshots (agent_id, mode, assets, checksum, created_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (agent_id) DO UPDATE
		SET mode=$2, assets=$3, checksum=$4, created_at=$5
	`, snap.AgentID, snap.Mode, snap.Assets, snap.Checksum, snap.CreatedAt)
	return err
}

func (s *Store) GetAssetSnapshot(ctx context.Context, agentID string) (*AssetSnapshot, error) {
	var snap AssetSnapshot

	err := s.pool.QueryRow(ctx, `
		SELECT agent_id, mode, assets, checksum, created_at
		FROM asset_snapshots WHERE agent_id=$1
	`, agentID).Scan(&snap.AgentID, &snap.Mode, &snap.Assets, &snap.Checksum, &snap.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func (s *Store) RecordAssetChange(ctx context.Context, agentID, changeType, assetName, oldVer, newVer, format string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO asset_changes (agent_id, change_type, asset_name, old_version, new_version, format, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, agentID, changeType, assetName, oldVer, newVer, format, time.Now())
	return err
}
