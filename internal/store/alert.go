package store

import (
	"context"
	"encoding/json"
	"log/slog"
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
	TicketEnabled     bool      `json:"ticket_enabled"`
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
	TicketProvider        string     `json:"ticket_provider,omitempty"`
	TicketKey             string     `json:"ticket_key,omitempty"`
	TicketURL             string     `json:"ticket_url,omitempty"`
	TicketStatus          string     `json:"ticket_status,omitempty"`
	TicketError           string     `json:"ticket_error,omitempty"`
	TicketAttempts        int        `json:"ticket_attempts,omitempty"`
	TicketSyncAttempts    int        `json:"ticket_sync_attempts,omitempty"`
	TicketSyncedAt        *time.Time `json:"ticket_synced_at,omitempty"`
	IntelThreatLevel      string     `json:"intel_threat_level,omitempty"`
	IntelExploited        bool       `json:"intel_exploited,omitempty"`
	EDRFindingID          *int64     `json:"edr_finding_id,omitempty"`
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
		&r.TicketEnabled,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	json.Unmarshal(channelsRaw, &r.Channels)
	return r, nil
}

const alertRuleColumns = `id, name, enabled, severity_filter, source_filter, agent_id_filter,
	asset_filter, min_cvss, cooldown_minutes, channels, asset_tag_filter,
	environment_filter, auto_remediate, ticket_enabled, created_at, updated_at`

const alertColumns = `id, rule_id, agent_id, cve_id, asset_name, severity, cvss_score, status,
	first_seen, last_seen, occurrence_count, resolved_at, source,
	remediation_campaign_id, remediation_error, ticket_provider, ticket_key, ticket_url,
	ticket_status, ticket_error, ticket_attempts, ticket_sync_attempts, ticket_synced_at,
	edr_finding_id`

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

// GetAlertRuleByName returns the rule with the given name.
func (s *Store) GetAlertRuleByName(ctx context.Context, name string) (AlertRule, error) {
	return scanAlertRule(s.pool.QueryRow(ctx, `
		SELECT `+alertRuleColumns+`
		FROM alert_rules WHERE name=$1
	`, name))
}

func (s *Store) CreateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	if r.AssetTagFilter == nil {
		r.AssetTagFilter = []string{}
	}
	channels, _ := json.Marshal(r.Channels)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO alert_rules (name, enabled, severity_filter, source_filter, agent_id_filter,
			asset_filter, min_cvss, cooldown_minutes, channels, asset_tag_filter,
			environment_filter, auto_remediate, ticket_enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING `+alertRuleColumns,
		r.Name, r.Enabled, r.SeverityFilter, r.SourceFilter, r.AgentIDFilter,
		r.AssetFilter, r.MinCVSS, r.CooldownMinutes, channels, r.AssetTagFilter,
		r.EnvironmentFilter, r.AutoRemediate, r.TicketEnabled)
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
			auto_remediate=$13, ticket_enabled=$14, updated_at=NOW()
		WHERE id=$1
		RETURNING `+alertRuleColumns,
		id, r.Name, r.Enabled, r.SeverityFilter, r.SourceFilter, r.AgentIDFilter,
		r.AssetFilter, r.MinCVSS, r.CooldownMinutes, channels, r.AssetTagFilter,
		r.EnvironmentFilter, r.AutoRemediate, r.TicketEnabled)
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
			status, first_seen, last_seen, occurrence_count, epss_score, kev, risk_score, risk_level,
			intel_threat_level, intel_exploited)
		SELECT $1,$2,$3,$4,$5,$6,$7,'open',NOW(),NOW(),1,
			COALESCE(cr.epss_score,0), COALESCE(cr.kev,false),
			COALESCE(cr.risk_score,0), COALESCE(cr.risk_level,''),
			COALESCE(cr.intel_threat_level,''), COALESCE(cr.intel_exploited,false)
		FROM (SELECT 1) x LEFT JOIN cve_results cr
			ON cr.agent_id=$2 AND cr.cve_id=$3 AND cr.asset_name=$4 AND cr.status='active'
		ON CONFLICT (rule_id, agent_id, cve_id, asset_name, COALESCE(edr_finding_id, 0)) WHERE status='open'
		DO UPDATE SET last_seen=NOW(), occurrence_count=alerts.occurrence_count+1,
			severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, source=EXCLUDED.source,
			epss_score=EXCLUDED.epss_score, kev=EXCLUDED.kev,
			risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level,
			intel_threat_level=EXCLUDED.intel_threat_level, intel_exploited=EXCLUDED.intel_exploited
		RETURNING id, (xmax = 0)
	`, rule.ID, agentID, cveID, assetName, severity, cvss, source).Scan(&id, &created)
	if err != nil {
		return id, created, err
	}
	if created {
		if e := s.appendSiemAlert(ctx, "alert.created", id, "open", "alerting"); e != nil {
			slog.Warn("siem alert created event failed", "alert_id", id, "error", e)
		}
	}
	return id, created, nil
}

// UpsertSLABreachAlert creates or refreshes an open SLA breach alert for an
// overdue (agent, cve, asset). Existing open alerts are deduplicated by the
// partial unique index and only bump occurrence_count/last_seen.
func (s *Store) UpsertSLABreachAlert(ctx context.Context, ruleID int64, agentID, cveID, assetName, severity string, cvss float64) (int64, bool, error) {
	var id int64
	var created bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alerts (rule_id, agent_id, cve_id, asset_name, severity, cvss_score, source,
			status, first_seen, last_seen, occurrence_count, epss_score, kev, risk_score, risk_level,
			intel_threat_level, intel_exploited)
		SELECT $1,$2,$3,$4,$5,$6,'sla','open',NOW(),NOW(),1,
			COALESCE(cr.epss_score,0), COALESCE(cr.kev,false),
			COALESCE(cr.risk_score,0), COALESCE(cr.risk_level,''),
			COALESCE(cr.intel_threat_level,''), COALESCE(cr.intel_exploited,false)
		FROM (SELECT 1) x LEFT JOIN cve_results cr
			ON cr.agent_id=$2 AND cr.cve_id=$3 AND cr.asset_name=$4 AND cr.status='active'
		ON CONFLICT (rule_id, agent_id, cve_id, asset_name, COALESCE(edr_finding_id, 0)) WHERE status='open'
		DO UPDATE SET last_seen=NOW(), occurrence_count=alerts.occurrence_count+1,
			severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score,
			epss_score=EXCLUDED.epss_score, kev=EXCLUDED.kev,
			risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level,
			intel_threat_level=EXCLUDED.intel_threat_level, intel_exploited=EXCLUDED.intel_exploited
		RETURNING id, (xmax = 0)
	`, ruleID, agentID, cveID, assetName, severity, cvss).Scan(&id, &created)
	if err != nil {
		return id, created, err
	}
	if created {
		if e := s.appendSiemAlert(ctx, "alert.created", id, "open", "sla-check"); e != nil {
			slog.Warn("siem sla alert created event failed", "alert_id", id, "error", e)
		}
	}
	return id, created, nil
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
	var rows pgx.Rows
	var err error
	if len(activeKeys) == 0 {
		rows, err = s.pool.Query(ctx, `
			UPDATE alerts SET status='resolved', resolved_at=NOW()
			WHERE agent_id=$1 AND status='open' AND edr_finding_id IS NULL
			RETURNING id
		`, agentID)
	} else {
		rows, err = s.pool.Query(ctx, `
			UPDATE alerts SET status='resolved', resolved_at=NOW()
			WHERE agent_id=$1 AND status='open' AND edr_finding_id IS NULL
			  AND (rule_id::text || '|' || cve_id || '|' || asset_name) <> ALL($2::text[])
			RETURNING id
		`, agentID, activeKeys)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if e := s.appendSiemAlert(ctx, "alert.resolved", id, "resolved", "match-resolve"); e != nil {
			slog.Warn("siem alert resolved event failed", "alert_id", id, "error", e)
		}
	}
	return rows.Err()
}

// ResolveSLABreachAlerts resolves open SLA alerts whose
// agent|cve|asset key is no longer in the active (still overdue) set.
func (s *Store) ResolveSLABreachAlerts(ctx context.Context, ruleID int64, activeKeys map[string]bool) (int64, error) {
	var rows pgx.Rows
	var err error
	if len(activeKeys) == 0 {
		rows, err = s.pool.Query(ctx, `
			UPDATE alerts SET status='resolved', resolved_at=NOW()
			WHERE rule_id=$1 AND status='open'
			RETURNING id
		`, ruleID)
	} else {
		rows, err = s.pool.Query(ctx, `
			UPDATE alerts SET status='resolved', resolved_at=NOW()
			WHERE rule_id=$1 AND status='open'
			  AND (agent_id || '|' || cve_id || '|' || asset_name) <> ALL($2::text[])
			RETURNING id
		`, ruleID, keysSlice(activeKeys))
	}
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return count, err
		}
		count++
		if e := s.appendSiemAlert(ctx, "alert.resolved", id, "resolved", "sla-check"); e != nil {
			slog.Warn("siem sla alert resolved event failed", "alert_id", id, "error", e)
		}
	}
	return count, rows.Err()
}

func keysSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *Store) ListAlerts(ctx context.Context, status, agentID, severity, assetFilter string, limit, offset int) ([]AlertDetail, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.cve_id, a.asset_name, a.severity,
			a.cvss_score, a.status, a.first_seen, a.last_seen, a.occurrence_count,
			a.resolved_at, a.source, a.remediation_campaign_id, a.remediation_error,
			a.ticket_provider, a.ticket_key, a.ticket_url, a.ticket_status,
			a.ticket_error, a.ticket_attempts, a.ticket_sync_attempts, a.ticket_synced_at,
			a.intel_threat_level, a.intel_exploited, a.edr_finding_id,
			COALESCE(r.name,'') AS rule_name
		FROM alerts a
		LEFT JOIN alert_rules r ON r.id=a.rule_id
		WHERE (''=$1 OR a.status=$1) AND (''=$2 OR a.agent_id=$2) AND (''=$3 OR a.severity=$3)
		  AND (''=$4 OR asset_name ILIKE '%' || $4 || '%')
		ORDER BY last_seen DESC LIMIT $5 OFFSET $6
	`, status, agentID, severity, assetFilter, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []AlertDetail
	for rows.Next() {
		var a AlertDetail
		if err := rows.Scan(&a.ID, &a.RuleID, &a.AgentID, &a.CVEID, &a.AssetName,
			&a.Severity, &a.CVSSScore, &a.Status, &a.FirstSeen, &a.LastSeen,
			&a.OccurrenceCount, &a.ResolvedAt, &a.Source,
			&a.RemediationCampaignID, &a.RemediationError,
			&a.TicketProvider, &a.TicketKey, &a.TicketURL, &a.TicketStatus,
			&a.TicketError, &a.TicketAttempts, &a.TicketSyncAttempts, &a.TicketSyncedAt,
			&a.IntelThreatLevel, &a.IntelExploited, &a.EDRFindingID, &a.RuleName); err != nil {
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
			a.ticket_provider, a.ticket_key, a.ticket_url, a.ticket_status,
			a.ticket_error, a.ticket_attempts, a.ticket_sync_attempts, a.ticket_synced_at,
			a.intel_threat_level, a.intel_exploited, a.edr_finding_id,
			COALESCE(r.name,''), COALESCE(ag.hostname,'')
		FROM alerts a
		LEFT JOIN alert_rules r ON r.id = a.rule_id
		LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.id=$1
	`, alertID).Scan(&d.ID, &d.RuleID, &d.AgentID, &d.CVEID, &d.AssetName,
		&d.Severity, &d.CVSSScore, &d.Status, &d.FirstSeen, &d.LastSeen,
		&d.OccurrenceCount, &d.ResolvedAt, &d.Source,
		&d.RemediationCampaignID, &d.RemediationError,
		&d.TicketProvider, &d.TicketKey, &d.TicketURL, &d.TicketStatus,
		&d.TicketError, &d.TicketAttempts, &d.TicketSyncAttempts, &d.TicketSyncedAt,
		&d.IntelThreatLevel, &d.IntelExploited, &d.EDRFindingID, &d.RuleName, &d.AgentHostname)
	return d, err
}

// ListTicketCreatePending returns open alerts whose rule enables tickets and
// which have not been created yet (or still have retry budget).
func (s *Store) ListTicketCreatePending(ctx context.Context, limit, maxAttempts int) ([]AlertDetail, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.cve_id, a.asset_name, a.severity,
			a.cvss_score, a.status, a.first_seen, a.last_seen, a.occurrence_count,
			a.resolved_at, a.source, a.remediation_campaign_id, a.remediation_error,
			a.ticket_provider, a.ticket_key, a.ticket_url, a.ticket_status,
			a.ticket_error, a.ticket_attempts, a.ticket_sync_attempts, a.ticket_synced_at,
			a.intel_threat_level, a.intel_exploited, a.edr_finding_id,
			COALESCE(r.name,''), COALESCE(ag.hostname,'')
		FROM alerts a
		JOIN alert_rules r ON r.id=a.rule_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE r.ticket_enabled AND a.status='open' AND a.ticket_key=''
		  AND a.ticket_attempts < $1
		ORDER BY a.id LIMIT $2
	`, maxAttempts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertDetails(rows)
}

// ListTicketSyncPending returns alerts with a created ticket whose local
// status has moved to ack/resolved but has not been synced yet.
func (s *Store) ListTicketSyncPending(ctx context.Context, limit, maxAttempts int) ([]AlertDetail, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.rule_id, a.agent_id, a.cve_id, a.asset_name, a.severity,
			a.cvss_score, a.status, a.first_seen, a.last_seen, a.occurrence_count,
			a.resolved_at, a.source, a.remediation_campaign_id, a.remediation_error,
			a.ticket_provider, a.ticket_key, a.ticket_url, a.ticket_status,
			a.ticket_error, a.ticket_attempts, a.ticket_sync_attempts, a.ticket_synced_at,
			a.intel_threat_level, a.intel_exploited, a.edr_finding_id,
			COALESCE(r.name,''), COALESCE(ag.hostname,'')
		FROM alerts a
		JOIN alert_rules r ON r.id=a.rule_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE r.ticket_enabled AND a.ticket_key<>'' AND a.status IN ('ack','resolved')
		  AND a.ticket_status<>a.status AND a.ticket_sync_attempts < $1
		ORDER BY a.id LIMIT $2
	`, maxAttempts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertDetails(rows)
}

func scanAlertDetails(rows pgx.Rows) ([]AlertDetail, error) {
	var out []AlertDetail
	for rows.Next() {
		var a AlertDetail
		if err := rows.Scan(&a.ID, &a.RuleID, &a.AgentID, &a.CVEID, &a.AssetName,
			&a.Severity, &a.CVSSScore, &a.Status, &a.FirstSeen, &a.LastSeen,
			&a.OccurrenceCount, &a.ResolvedAt, &a.Source,
			&a.RemediationCampaignID, &a.RemediationError,
			&a.TicketProvider, &a.TicketKey, &a.TicketURL, &a.TicketStatus,
			&a.TicketError, &a.TicketAttempts, &a.TicketSyncAttempts, &a.TicketSyncedAt,
			&a.IntelThreatLevel, &a.IntelExploited, &a.EDRFindingID, &a.RuleName, &a.AgentHostname); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) MarkTicketCreated(ctx context.Context, alertID int64, provider, key, url string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET ticket_provider=$2, ticket_key=$3, ticket_url=$4,
			ticket_status='open', ticket_error='', ticket_attempts=0,
			ticket_sync_attempts=0, ticket_synced_at=NOW()
		WHERE id=$1
	`, alertID, provider, key, url)
	return err
}

func (s *Store) MarkTicketCreateFailed(ctx context.Context, alertID int64, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET ticket_attempts=ticket_attempts+1, ticket_error=$2,
			ticket_synced_at=NOW()
		WHERE id=$1
	`, alertID, errMsg)
	return err
}

func (s *Store) MarkTicketSynced(ctx context.Context, alertID int64, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET ticket_status=$2, ticket_error='', ticket_sync_attempts=0,
			ticket_synced_at=NOW()
		WHERE id=$1
	`, alertID, status)
	return err
}

func (s *Store) MarkTicketSyncFailed(ctx context.Context, alertID int64, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET ticket_sync_attempts=ticket_sync_attempts+1, ticket_error=$2,
			ticket_synced_at=NOW()
		WHERE id=$1
	`, alertID, errMsg)
	return err
}

func (s *Store) ResetTicketRetry(ctx context.Context, alertID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET ticket_attempts=0, ticket_sync_attempts=0, ticket_error=''
		WHERE id=$1
	`, alertID)
	return err
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

func (s *Store) SetAlertStatus(ctx context.Context, alertID int64, status, actor string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status=$2, resolved_at=CASE WHEN $2='resolved' THEN NOW() ELSE resolved_at END
		WHERE id=$1
	`, alertID, status)
	if err != nil {
		return err
	}
	if status == "ack" || status == "resolved" {
		eventType := "alert.acknowledged"
		if status == "resolved" {
			eventType = "alert.resolved"
		}
		if e := s.appendSiemAlert(ctx, eventType, alertID, status, actor); e != nil {
			slog.Warn("siem alert status event failed", "alert_id", alertID, "status", status, "error", e)
		}
	}
	return nil
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
