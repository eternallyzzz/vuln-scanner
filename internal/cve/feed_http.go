package cve

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// conditionalGet performs a request carrying any cached validators from st.
// It returns the response body, status code, and the updated validators.
func conditionalGet(ctx context.Context, client *http.Client, method, rawURL string,
	body io.Reader, headers map[string]string, st FeedState) ([]byte, int, FeedState, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, 0, st, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if st.ETag != "" {
		req.Header.Set("If-None-Match", st.ETag)
	}
	if st.LastModified != "" {
		req.Header.Set("If-Modified-Since", st.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, st, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, st, fmt.Errorf("read %s: %w", rawURL, err)
	}

	next := st
	if et := resp.Header.Get("ETag"); et != "" {
		next.ETag = et
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		next.LastModified = lm
	}
	return data, resp.StatusCode, next, nil
}
