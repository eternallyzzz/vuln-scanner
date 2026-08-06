package webdbscan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ScanDB probes one database service and returns the detected product(s).
// Credentials are required for PostgreSQL version detection; MySQL and Redis
// versions are available from the wire banner without authentication.
func ScanDB(ctx context.Context, rawTarget, dbType string, cred *Credential, cfg Config) (DBResult, error) {
	dbType = strings.ToLower(strings.TrimSpace(dbType))
	if !IsValidDBType(dbType) {
		return DBResult{}, fmt.Errorf("unsupported db_type %q", dbType)
	}
	target, err := NormalizeDBTarget(rawTarget, dbType)
	if err != nil {
		return DBResult{}, err
	}
	switch dbType {
	case "mysql":
		return scanMySQL(ctx, target, cfg)
	case "redis":
		return scanRedis(ctx, target, cred, cfg)
	case "postgresql":
		return scanPostgreSQL(ctx, target, cred, cfg)
	}
	return DBResult{}, fmt.Errorf("unsupported db_type %q", dbType)
}

func dialTimeout(target string, cfg Config) (net.Conn, error) {
	timeout := cfg.Timeout()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return net.DialTimeout("tcp", target, timeout)
}

func setDeadline(conn net.Conn, cfg Config) {
	timeout := cfg.Timeout()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
}

func scanMySQL(ctx context.Context, target string, cfg Config) (DBResult, error) {
	conn, err := dialTimeout(target, cfg)
	if err != nil {
		return DBResult{}, fmt.Errorf("mysql connect: %w", err)
	}
	defer conn.Close()
	setDeadline(conn, cfg)

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return DBResult{}, fmt.Errorf("mysql handshake: %w", err)
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length < 1 || length > 1<<20 {
		return DBResult{}, fmt.Errorf("mysql handshake: invalid packet length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return DBResult{}, fmt.Errorf("mysql handshake: %w", err)
	}
	if payload[0] != 0x0a {
		return DBResult{}, fmt.Errorf("mysql handshake: unexpected protocol version %d", payload[0])
	}
	nul := bytes.IndexByte(payload[1:], 0)
	if nul < 0 {
		return DBResult{}, fmt.Errorf("mysql handshake: missing server version")
	}
	rawVersion := string(payload[1 : 1+nul])
	version := cleanVersion(rawVersion)
	result := DBResult{DBType: "mysql", Version: version}
	if version != "" {
		result.Products = []Product{{Name: "mysql", Version: version, Evidence: rawVersion}}
	}
	return result, nil
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, "-+"); i > 0 {
		v = v[:i]
	}
	return v
}

func scanRedis(ctx context.Context, target string, cred *Credential, cfg Config) (DBResult, error) {
	conn, err := dialTimeout(target, cfg)
	if err != nil {
		return DBResult{}, fmt.Errorf("redis connect: %w", err)
	}
	defer conn.Close()
	setDeadline(conn, cfg)

	rc := &respClient{conn: conn, br: bufio.NewReader(conn)}
	authRequired := false
	if _, err := rc.command("PING"); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "noauth") || strings.Contains(msg, "operation not permitted") {
			authRequired = true
		} else {
			return DBResult{}, fmt.Errorf("redis ping: %w", err)
		}
	}
	if authRequired {
		if cred == nil || cred.Password == "" {
			return DBResult{DBType: "redis", AuthRequired: true}, nil
		}
		args := []string{"AUTH"}
		if cred.Username != "" {
			args = append(args, cred.Username, cred.Password)
		} else {
			args = append(args, cred.Password)
		}
		if _, err := rc.command(args...); err != nil {
			return DBResult{}, fmt.Errorf("redis auth: %w", err)
		}
	}
	info, err := rc.command("INFO", "server")
	if err != nil {
		return DBResult{}, fmt.Errorf("redis info: %w", err)
	}
	version := parseRedisVersion(info)
	result := DBResult{DBType: "redis", Version: version, AuthRequired: authRequired}
	if version != "" {
		result.Products = []Product{{Name: "redis", Version: version, Evidence: "INFO server"}}
	}
	return result, nil
}

var redisVersionRe = regexp.MustCompile(`(?m)^redis_version:([0-9][A-Za-z0-9_.-]*)`)

func parseRedisVersion(info string) string {
	if m := redisVersionRe.FindStringSubmatch(info); len(m) > 1 {
		return cleanVersion(m[1])
	}
	return ""
}

// respClient is a minimal Redis RESP client supporting PING/AUTH/INFO.
type respClient struct {
	conn net.Conn
	br   *bufio.Reader
}

func (c *respClient) command(args ...string) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.conn.Write([]byte(sb.String())); err != nil {
		return "", err
	}
	return c.readReply()
}

func (c *respClient) readReply() (string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("redis empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return "", errors.New(line[1:])
	case ':':
		return line[1:], nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", err
		}
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.br, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", err
		}
		if n <= 0 {
			return "", nil
		}
		var parts []string
		for i := 0; i < n; i++ {
			s, err := c.readReply()
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, "\n"), nil
	}
	return "", fmt.Errorf("redis unexpected reply %q", line)
}

func scanPostgreSQL(ctx context.Context, target string, cred *Credential, cfg Config) (DBResult, error) {
	if cred == nil || strings.TrimSpace(cred.Username) == "" {
		// Without credentials the PostgreSQL wire protocol does not expose
		// the server version, so only reachability and auth requirement are
		// recorded.
		conn, err := dialTimeout(target, cfg)
		if err != nil {
			return DBResult{}, fmt.Errorf("postgresql connect: %w", err)
		}
		conn.Close()
		return DBResult{DBType: "postgresql", AuthRequired: true}, nil
	}
	timeout := cfg.Timeout()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := pgx.Connect(ctx2, postgresDSN(target, cred.Username, cred.Password, timeout))
	if err != nil {
		return DBResult{}, fmt.Errorf("postgresql connect: %w", err)
	}
	defer conn.Close(ctx2)
	var version string
	if err := conn.QueryRow(ctx2, "SELECT version()").Scan(&version); err != nil {
		return DBResult{}, fmt.Errorf("postgresql version query: %w", err)
	}
	parsed := parsePostgreSQLVersion(version)
	result := DBResult{DBType: "postgresql", Version: parsed}
	if parsed != "" {
		result.Products = []Product{{Name: "postgresql", Version: parsed, Evidence: version}}
	}
	return result, nil
}

func postgresDSN(target, username, password string, timeout time.Duration) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   target,
		Path:   "/postgres",
	}
	q := u.Query()
	q.Set("sslmode", "disable")
	q.Set("connect_timeout", strconv.Itoa(int(timeout.Seconds())))
	u.RawQuery = q.Encode()
	return u.String()
}

var postgresVersionRe = regexp.MustCompile(`(?i)PostgreSQL\s+([0-9]+(?:\.[0-9]+)*)`)

func parsePostgreSQLVersion(version string) string {
	if m := postgresVersionRe.FindStringSubmatch(version); len(m) > 1 {
		return m[1]
	}
	return ""
}
