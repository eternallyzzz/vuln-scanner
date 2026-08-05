package server

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"vuln-scanner/internal/store"
)

const userTokenTTL = 12 * time.Hour

// UserClaims is the JWT payload for dashboard/login sessions. The
// `typ: "user"` distinction keeps user tokens from being confused with agent
// tokens issued by AgentAuth.
type UserClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type UserAuth struct {
	secret []byte
	ttl    time.Duration
}

func NewUserAuth(jwtSecret string) *UserAuth {
	return newUserAuth(jwtSecret, userTokenTTL)
}

func newUserAuth(jwtSecret string, ttl time.Duration) *UserAuth {
	return &UserAuth{secret: []byte(jwtSecret), ttl: ttl}
}

func (a *UserAuth) IssueToken(u *store.User) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(a.ttl)
	claims := UserClaims{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", u.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (a *UserAuth) ValidateToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid user token")
	}
	// Agent tokens are MapClaims with agent_id and would otherwise parse
	// into a zero-valued UserClaims; require a real user identity.
	if claims.UserID == 0 || claims.Username == "" || claims.Role == "" {
		return nil, fmt.Errorf("token is not a user token")
	}
	return claims, nil
}

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
