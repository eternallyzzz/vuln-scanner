package siem

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type splunkSender struct {
	cfg    *HECConfig
	token  string
	client *http.Client
}

func (s *splunkSender) Name() string {
	return "splunk_hec"
}

// Send posts newline-delimited HEC envelopes so Splunk ingests one event per
// line in a single request.
func (s *splunkSender) Send(ctx context.Context, events []Event) error {
	var b strings.Builder
	for _, e := range events {
		envelope := map[string]interface{}{
			"time":       e.OccurredAt.Unix(),
			"index":      s.cfg.Index,
			"sourcetype": s.cfg.SourceType,
			"source":     "vuln-scanner",
			"event":      e.Envelope(),
		}
		line, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return doPOST(ctx, s.client, s.cfg.URL, "Splunk "+s.token, []byte(b.String()))
}
