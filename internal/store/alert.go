package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type AlertRule struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	SeverityFilter    string    `json:"severity_filter"`
	SourceFilter      string    `json:"source_filter"`
	AgentIDFilter     string    `json:"agent_id_filter"`
	AssetFilter       string    `json:"asset_filter"`
	MinCVSS           float64   `json:"min_cvss"`
	CooldownMinutes   int       `json:"cooldown_minutes"`
	Channels          []string  `json:"channels"`
	AssetTagFilter    []string  `json:"asset_tag_filter"`
	EnvironmentFilter string    `json:"environment_filter"`
	AutoRemediate     bool      `json:"auto_remediate"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Alert struct {
	ID                    int64      `json:"id"`
	RuleID                int64      `json:"rule_id"`
	AgentID               string     `json:"agent_id"`
	CVEID                 string     `json:"cve_id"`
	AssetName             string     `json:"asset_name"`
	Severity              string     `json:"severity"`
	CVSSScore             float64    `json:"cvss_score"`
	Status                string     `json:"status"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
	OccurrenceCount       int        `json:"occurrence_count"`
	ResolvedAt            *time.Time `json:"resolved_at,omitempty"`
	Source                string     `json:"source"`
	RemediationCampaignID *int64     `json:"remediation_campaign_id,omitempty"`
	RemediationError      string     `json:"remediation_error,omitempty"`
}

type AlertDetail struct {
	Alert
	RuleName      string `json:"rule_name"`
	AgentHostname string `json:"agent_hostname"`
}

type AlertDelivery struct {
	ID           int64      `json:"id"`
	AlertID      int64      `json:"alert_id"`
	Channel      string     `json:"channel"`
	Status       string     `json:"status"`
	AttemptCount int        `json:"attempt_count"`
	LastError    string     `json:"last_error"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
}

func scanAlertRule(row pgx.Row) (AlertRule, error) {
	var r AlertRule
	var channelsRaw []byte
	err := row.Scan(&r.ID, &r.Name, &r.Enabled, &r.SeverityFilter, &r.SourceFilter,
		&r.AgentIDFilter, &r.AssetFilter, &r.MinCVSS, &r.CooldownMinutes,
		&channelsRaw, &r.AssetTagFilter, &r.EnvironmentFilter, &r.AutoRemediate,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	json.Unmarshal(channelsRaw, &r.Channels)
	return r, nil
}

const alertRuleColumns = `id, name, enabled, severity_filter, source_filter, agent_id_filter,
	asset_filter, min_cvss, cooldown_minutes, channels, asset_tag_filter,
	environment_filter, auto_remediate, created_at, updated_at`

const alertColumns = `id, rule_id, agent_id, cve_id, asset_name, severity, cvss_score, status,
	first_seen, last_seen, occurrence_count, resolved_at, source,
	remediation_campaign_id, remediation_error`

func (s *Store) ListEnabledAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+alertRuleColumns+`
		FROM alert_rules WHERE enabled = TRUE ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []AlertRule
	for rows.Next() {
		r, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+alertRuleColumns+`
		FROM alert_rules ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []AlertRule
	for rows.Next() {
		r, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) GetAlertRule(ctx context.Context, id int64) (AlertRule, error) {
	return scanAlertRule(s.pool.QueryRow(ctx, `
		SELECT `+alertRuleColumns+`
		FROM alert_rules WHERE id=$1
	`, id))
}

func (s *Store) CreateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	if r.AssetTagFilter == nil {
		r.AssetTagFilter = []string{}
	}
	channels, _ := json.Marshal(r.Channels)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO alert_rules (name, enabled, severity_filter, source_filter, agent_id_filter,
			asset_filter, min_cvss, cooldown_minutes, channels, asset_tag_filter,
			environment_filter, auto_remediate)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+alertRuleColumns,
		r.Name, r.Enabled, r.SeverityFilter, r.SourceFilter, r.AgentIDFilter,
		r.AssetFilter, r.MinCVSS, r.CooldownMinutes, channels, r.AssetTagFilter,
		r.EnvironmentFilter, r.AutoRemediate)
	return scanAlertRule(row)
}

func (s *Store) UpdateAlertRule(ctx context.Context, id int64, r AlertRule) (AlertRule, error) {
	if r.AssetTagFilter == nil {
		r.AssetTagFilter = []string{}
	}
	channels, _ := json.Marshal(r.Channels)
	row := s.pool.QueryRow(ctx, `
		UPDATE alert_rules SET name=$2, enabled=$3, severity_filter=$4, source_filter=$5,
			agent_id_filter=$6, asset_filter=$7, min_cvss=$8, cooldown_minutes=$9,
			channels=$10, asset_tag_filter=$11, environment_filter=$12,
			auto_remediate=$13, updated_at=NOW()
		WHERE id=$1
		RETURNING `+alertRuleColumns,
		id, r.Name, r.Enabled, r.SeverityFilter, r.SourceFilter, r.AgentIDFilter,
		r.AssetFilter, r.MinCVSS, r.CooldownMinutes, channels, r.AssetTagFilter,
		r.EnvironmentFilter, r.AutoRemediate)
	return scanAlertRule(row)
}

func (s *Store) DeleteAlertRule(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id=$1`, id)
	return err
}

// UpsertAlertFromResult returns the alert id and whether a new alert was
// created. Existing open alerts are refreshed (last_seen, occurrence_count);
// a recently resolved alert within the rule cooldown is left untouched.
func (s *Store) UpsertAlertFromResult(ctx context.Context, rule AlertRule, agentID, cveID, assetName, severity, source string, cvss float64) (int64, bool, error) {
	if rule.CooldownMinutes > 0 {
		var resolvedAt *time.Time
		err := s.pool.QueryRow(ctx, `
			SELECT resolved_at FROM alerts
			WHERE rule_id=$1 AND agent_id=$2 AND cve_id=$3 AND asset_name=$4
			  AND status='resolved'
			ORDER BY resolved_at DESC LIMIT 1
		`, rule.ID, agentID, cveID, assetName).Scan(&resolvedAt)
		if err == nil && resolvedAt != nil &&
			resolvedAt.Add(time.Duration(rule.CooldownMinutes)*time.Minute).After(time.Now()) {
			return 0, false, nil
		}
	}

	var id int64
	var created bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alerts (rule_id, agent_id, cve_id, asset_name, severity, cvss_score, source,
			status, first_seen, last_seen, occurrence_count, epss_score, kev, risk_score, risk_level)
		SELECT $1,$2,$3,$4,$5,$6,$7,'open',NOW(),NOW(),1,
			COALESCE(cr.epss_score,0), COALESCE(cr.kev,false),
			COALESCE(cr.risk_score,0), COALESCE(cr.risk_level,'')
		FROM (SELECT 1) x LEFT JOIN cve_results cr
			ON cr.agent_id=$2 AND cr.cve_id=$3 AND cr.asset_name=$4 AND cr.status='active'
		ON CONFLICT (rule_id, agent_id, cve_id, asset_name) WHERE status='open'
		DO UPDATE SET last_seen=NOW(), occurrence_count=alerts.occurrence_count+1,
			severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, source=EXCLUDED.source,
			epss_score=EXCLUDED.epss_score, kev=EXCLUDED.kev,
			risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level
		RETURNING id, (xmax = 0)
	`, rule.ID, agentID, cveID, assetName, severity, cvss, source).Scan(&id, &created)
	return id, created, err
}

func (s *Store) CreateAlertDeliveries(ctx context.Context, alertID int64, channels []string) error {
	for _, ch := range channels {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO alert_deliveries (alert_id, channel)
			VALUES ($1,$2) ON CONFLICT (alert_id, channel) DO NOTHING
		`, alertID, ch); err != nil {
			return err
		}
	}
	return nil
}

// ResolveInactiveAlerts marks open alerts resolved when their
// rule|cve|asset key is not in the active set (no longer matched).
func (s *Store) ResolveInactiveAlerts(ctx context.Context, agentID string, activeKeys []string) error {
	if len(activeKeys) == 0 {
		_, err := s.pool.Exec(ctx, `
			UPDATE alerts SET status='resolved', resolved_at=NOW()
			WHERE agent_id=$1 AND status='open'
		`, agentID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status='resolved', resolved_at=NOW()
		WHERE agent_id=$1 AND status='open'
		  AND (rule_id::text || '|' || cve_id || '|' || asset_name) <> ALL($2::text[])
	`, agentID, activeKeys)
	return err
}

func (s *Store) ListAlerts(ctx context.Context, status, agentID, severity, assetFilter string, limit, offset int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+alertColumns+`
		FROM alerts
		WHERE (''=$1 OR status=$1) AND (''=$2 OR agent_id=$2) AND (''=$3 OR severity=$3)
		  AND (''=$4 OR asset_name ILIKE '%' || $4 || '%')
		ORDER BY last_seen DESC LIMIT $5 OFFSET $6
	`, status, agentID, severity, assetFilter, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.RuleID, &a.AgentID, &a.CVEID, &a.AssetName,
			&a.Severity, &a.CVSSScore, &a.Status, &a.FirstSeen, &a.LastSeen,
			&a.OccurrenceCount, &a.ResolvedAt, &a.Source,
			&a.RemediationCampaignID, &a.RemediationError); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (s *Store) GetAlertDetail(ctx context.Context, alertID int64) (AlertDetail, error) {
	var d AlertDetail
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.cve_id, a.asset_name, a.severity,
			a.cvss_score, a.status, a.first_seen, a.last_seen, a.occurrence_count,
			a.resolved_at, a.source, a.remediation_campaign_id, a.remediation_error,
			COALESCE(r.name,''), COALESCE(ag.hostname,'')
		FROM alerts a
		LEFT JOIN alert_rules r ON r.id = a.rule_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.id=$1
	`, alertID).Scan(&d.ID, &d.RuleID, &d.AgentID, &d.CVEID, &d.AssetName,
		&d.Severity, &d.CVSSScore, &d.Status, &d.FirstSeen, &d.LastSeen,
		&d.OccurrenceCount, &d.ResolvedAt, &d.Source,
		&d.RemediationCampaignID, &d.RemediationError, &d.RuleName, &d.AgentHostname)
	return d, err
}

// SetAlertRemediation records the campaign (or skip reason) for an alert.
// The WHERE guard keeps the first recorded remediation, so a campaign is
// never overwritten by a later failed attempt.
func (s *Store) SetAlertRemediation(ctx context.Context, alertID int64, campaignID *int64, errText string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET remediation_campaign_id=$2, remediation_error=$3
		WHERE id=$1 AND remediation_campaign_id IS NULL
	`, alertID, campaignID, errText)
	return err
}

func (s *Store) SetAlertStatus(ctx context.Context, alertID int64, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status=$2, resolved_at=CASE WHEN $2='resolved' THEN NOW() ELSE resolved_at END
		WHERE id=$1
	`, alertID, status)
	return err
}

func (s *Store) ListPendingAlertDeliveries(ctx context.Context, limit int) ([]AlertDelivery, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, alert_id, channel, status, attempt_count, last_error, sent_at
		FROM alert_deliveries
		WHERE status='pending'
		ORDER BY id LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AlertDelivery
	for rows.Next() {
		var d AlertDelivery
		if err := rows.Scan(&d.ID, &d.AlertID, &d.Channel, &d.Status,
			&d.AttemptCount, &d.LastError, &d.SentAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) MarkAlertDeliverySent(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alert_deliveries SET status='sent', sent_at=NOW(), last_error='' WHERE id=$1
	`, id)
	return err
}

func (s *Store) MarkAlertDeliveryFailed(ctx context.Context, id int64, errMsg string, maxAttempts int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alert_deliveries SET attempt_count=attempt_count+1, last_error=$2,
			status=CASE WHEN attempt_count+1 >= $3 THEN 'failed' ELSE 'pending' END
		WHERE id=$1
	`, id, errMsg, maxAttempts)
	return err
}
