package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AgentAuth struct {
	mu sync.RWMutex

	jwtSecret  []byte
	tokenTTL   time.Duration
	regCodeTTL time.Duration
	regCodes   map[string]*RegCodeEntry
}

type RegCodeEntry struct {
	AgentID   string
	Hostname  string
	Platform  string
	ExpiresAt time.Time
}

func NewAgentAuth(jwtSecret string) *AgentAuth {
	a := &AgentAuth{
		jwtSecret:  []byte(jwtSecret),
		tokenTTL:   24 * time.Hour,
		regCodeTTL: 60 * time.Second,
		regCodes:   make(map[string]*RegCodeEntry),
	}
	go a.cleanExpiredCodes()
	return a
}

func (a *AgentAuth) GenerateRegCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, 6)
	for i := range code {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[n.Int64()]
	}
	return string(code)
}

func (a *AgentAuth) StoreRegCode(code, agentID, hostname, platform string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.regCodes[code] = &RegCodeEntry{
		AgentID:   agentID,
		Hostname:  hostname,
		Platform:  platform,
		ExpiresAt: time.Now().Add(a.regCodeTTL),
	}
}

func (a *AgentAuth) ConsumeRegCode(code string) (*RegCodeEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.regCodes[code]
	if !ok || time.Now().After(entry.ExpiresAt) {
		if ok {
			delete(a.regCodes, code)
		}
		return nil, false
	}
	delete(a.regCodes, code)
	return entry, true
}

func (a *AgentAuth) IssueToken(agentID string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(a.tokenTTL)

	claims := jwt.MapClaims{
		"agent_id": agentID,
		"iat":      now.Unix(),
		"exp":      expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(a.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, expiresAt, nil
}

func (a *AgentAuth) ValidateToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.jwtSecret, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}

	agentID, ok := claims["agent_id"].(string)
	if !ok {
		return "", fmt.Errorf("missing agent_id in token")
	}

	return agentID, nil
}

func (a *AgentAuth) TokenTTL() time.Duration {
	return a.tokenTTL
}

func (a *AgentAuth) cleanExpiredCodes() {
	for range time.NewTicker(30 * time.Second).C {
		a.mu.Lock()
		now := time.Now()
		for code, e := range a.regCodes {
			if now.After(e.ExpiresAt) {
				delete(a.regCodes, code)
			}
		}
		a.mu.Unlock()
	}
}

func HashFingerprint(fp string) string {
	h := sha256.Sum256([]byte(fp))
	return fmt.Sprintf("%x", h[:])
}

func ServerAddrFromContext(ctx context.Context) string {
	if addr, ok := ctx.Value("server_addr").(string); ok {
		return addr
	}
	return ""
}
