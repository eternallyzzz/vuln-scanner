package llm

import "context"

type Request struct {
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Response struct {
	Content    string `json:"content"`
	TokensUsed int    `json:"tokens_used"`
	Model      string `json:"model"`
}

type Provider interface {
	Chat(ctx context.Context, req *Request) (*Response, error)
	Name() string
	Enabled() bool
}
