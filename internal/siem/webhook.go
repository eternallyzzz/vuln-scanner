package siem

import (
	"context"
	"encoding/json"
	"net/http"
)

type webhookSender struct {
	url    string
	secret string
	client *http.Client
}

func (s *webhookSender) Name() string {
	return "webhook"
}

// Send posts the batch as {"events":[...]} with an optional HMAC signature.
func (s *webhookSender) Send(ctx context.Context, events []Event) error {
	envelopes := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		envelopes = append(envelopes, e.Envelope())
	}
	body, err := json.Marshal(map[string]interface{}{"events": envelopes})
	if err != nil {
		return err
	}
	return doPOSTHeaders(ctx, s.client, s.url, "", s.secret, body)
}
