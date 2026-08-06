package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type jiraClient struct {
	cfg    *Config
	client *http.Client
}

type jiraFields struct {
	Project     json.RawMessage `json:"project"`
	Summary     string          `json:"summary"`
	Description string          `json:"description"`
	IssueType   json.RawMessage `json:"issuetype"`
	Priority    json.RawMessage `json:"priority"`
}

type jiraIssuePayload struct {
	Fields jiraFields `json:"fields"`
}

type jiraIssueResponse struct {
	Key  string `json:"key"`
	Self string `json:"self"`
}

type jiraTransitionPayload struct {
	Transition struct {
		ID string `json:"id"`
	} `json:"transition"`
}

func (c *jiraClient) create(ctx context.Context, in AlertInfo) (TicketRef, error) {
	project, _ := json.Marshal(map[string]string{"key": c.cfg.Project})
	issueType, _ := json.Marshal(map[string]string{"name": c.cfg.IssueType})
	priority, _ := json.Marshal(map[string]string{"name": jiraPriority(in.Severity)})
	payload := jiraIssuePayload{Fields: jiraFields{
		Project:     project,
		Summary:     jiraSummary(in),
		Description: ticketDescription(in),
		IssueType:   issueType,
		Priority:    priority,
	}}
	var resp jiraIssueResponse
	err := doJSON(ctx, c.client, http.MethodPost, c.cfg.BaseURL+"/rest/api/2/issue",
		basicAuthHeader(c.cfg), payload, &resp)
	if err != nil {
		return TicketRef{}, err
	}
	if resp.Key == "" {
		return TicketRef{}, fmt.Errorf("jira create response missing key")
	}
	ticketURL := resp.Self
	if ticketURL == "" {
		ticketURL = c.cfg.BaseURL + "/browse/" + resp.Key
	}
	return TicketRef{Provider: "jira", Key: resp.Key, URL: ticketURL}, nil
}

func (c *jiraClient) syncStatus(ctx context.Context, ref TicketRef, status string) error {
	key := url.PathEscape(ref.Key)
	switch status {
	case "ack":
		if id := strings.TrimSpace(c.cfg.JiraAckTransitionID); id != "" {
			var body jiraTransitionPayload
			body.Transition.ID = id
			return doJSON(ctx, c.client, http.MethodPost,
				c.cfg.BaseURL+"/rest/api/2/issue/"+key+"/transitions",
				basicAuthHeader(c.cfg), body, nil)
		}
		return doJSON(ctx, c.client, http.MethodPost,
			c.cfg.BaseURL+"/rest/api/2/issue/"+key+"/comment",
			basicAuthHeader(c.cfg),
			map[string]string{"body": "VulnScanner: alert acknowledged"}, nil)
	case "resolved":
		if id := strings.TrimSpace(c.cfg.JiraResolvedTransitionID); id != "" {
			var body jiraTransitionPayload
			body.Transition.ID = id
			return doJSON(ctx, c.client, http.MethodPost,
				c.cfg.BaseURL+"/rest/api/2/issue/"+key+"/transitions",
				basicAuthHeader(c.cfg), body, nil)
		}
		return doJSON(ctx, c.client, http.MethodPost,
			c.cfg.BaseURL+"/rest/api/2/issue/"+key+"/comment",
			basicAuthHeader(c.cfg),
			map[string]string{"body": "VulnScanner: alert resolved"}, nil)
	default:
		return fmt.Errorf("unsupported ticket sync status %q", status)
	}
}

func jiraPriority(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "Highest"
	case "HIGH":
		return "High"
	case "LOW":
		return "Low"
	case "MEDIUM":
		return "Medium"
	default:
		return "Medium"
	}
}

func jiraSummary(in AlertInfo) string {
	return fmt.Sprintf("[VulnScanner] %s %s on %s", in.Severity, in.CVEID, in.AssetName)
}

func ticketDescription(in AlertInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Alert ID: %d\n", in.AlertID)
	fmt.Fprintf(&b, "Rule: %s\n", in.RuleName)
	fmt.Fprintf(&b, "Agent: %s (%s)\n", in.AgentID, in.AgentHostname)
	fmt.Fprintf(&b, "CVE: %s\n", in.CVEID)
	fmt.Fprintf(&b, "Asset: %s\n", in.AssetName)
	fmt.Fprintf(&b, "Severity: %s\n", in.Severity)
	fmt.Fprintf(&b, "CVSS: %.1f\n", in.CVSS)
	fmt.Fprintf(&b, "Source: %s\n", in.Source)
	if !in.DetectedAt.IsZero() {
		fmt.Fprintf(&b, "Detected: %s\n", in.DetectedAt.Format(time.RFC3339))
	}
	return b.String()
}
