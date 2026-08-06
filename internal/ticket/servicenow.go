package ticket

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type serviceNowClient struct {
	cfg    *Config
	client *http.Client
}

type serviceNowCreatePayload struct {
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	Urgency          int    `json:"urgency"`
	Impact           int    `json:"impact"`
}

type serviceNowCreateResponse struct {
	Result struct {
		SysID  string `json:"sys_id"`
		Number string `json:"number"`
	} `json:"result"`
}

func (c *serviceNowClient) create(ctx context.Context, in AlertInfo) (TicketRef, error) {
	payload := serviceNowCreatePayload{
		ShortDescription: jiraSummary(in),
		Description:      ticketDescription(in),
		Urgency:          serviceNowPriority(in.Severity),
		Impact:           serviceNowPriority(in.Severity),
	}
	var resp serviceNowCreateResponse
	err := doJSON(ctx, c.client, http.MethodPost,
		c.cfg.BaseURL+"/api/now/table/"+c.cfg.ServiceNowTable,
		basicAuthHeader(c.cfg), payload, &resp)
	if err != nil {
		return TicketRef{}, err
	}
	if resp.Result.SysID == "" {
		return TicketRef{}, fmt.Errorf("servicenow create response missing sys_id")
	}
	key := resp.Result.Number
	if key == "" {
		key = resp.Result.SysID
	}
	return TicketRef{
		Provider: "servicenow",
		Key:      key,
		URL:      c.cfg.BaseURL + "/api/now/table/" + c.cfg.ServiceNowTable + "/" + url.PathEscape(resp.Result.SysID),
	}, nil
}

func (c *serviceNowClient) syncStatus(ctx context.Context, ref TicketRef, status string) error {
	state := 0
	var note string
	switch status {
	case "ack":
		state = c.cfg.ServiceNowAckState
		note = "VulnScanner: alert acknowledged"
	case "resolved":
		state = c.cfg.ServiceNowResolvedState
		note = "VulnScanner: alert resolved"
	default:
		return fmt.Errorf("unsupported ticket sync status %q", status)
	}
	key := url.PathEscape(strings.Split(ref.Key, "/")[0])
	body := map[string]interface{}{
		"state":      state,
		"work_notes": note,
	}
	return doJSON(ctx, c.client, http.MethodPatch,
		c.cfg.BaseURL+"/api/now/table/"+c.cfg.ServiceNowTable+"/"+key,
		basicAuthHeader(c.cfg), body, nil)
}

func serviceNowPriority(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return 1
	case "LOW":
		return 3
	default:
		return 2
	}
}
