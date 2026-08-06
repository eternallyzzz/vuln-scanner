package webdbscan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestScanMySQLHandshake(t *testing.T) {
	addr := startFakeServer(t, func(conn net.Conn) {
		defer conn.Close()
		payload := append([]byte{0x0a}, []byte("8.0.36-log")...)
		payload = append(payload, 0)
		payload = append(payload, make([]byte, 16)...)
		hdr := []byte{byte(len(payload) & 0xff), byte((len(payload) >> 8) & 0xff), byte((len(payload) >> 16) & 0xff), 0}
		conn.Write(append(hdr, payload...))
	})
	res, err := ScanDB(context.Background(), addr, "mysql", nil, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.DBType != "mysql" || res.Version != "8.0.36" {
		t.Fatalf("unexpected mysql result: %+v", res)
	}
	if len(res.Products) != 1 || res.Products[0].Name != "mysql" || res.Products[0].Version != "8.0.36" {
		t.Fatalf("unexpected products: %+v", res.Products)
	}
}

func TestScanMySQLBadProtocol(t *testing.T) {
	addr := startFakeServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.Write([]byte{3, 0, 0, 0, 0xff, 0, 0})
	})
	if _, err := ScanDB(context.Background(), addr, "mysql", nil, *DefaultConfig().Normalized()); err == nil {
		t.Fatal("expected error for bad mysql protocol")
	}
}

func TestScanRedisOpen(t *testing.T) {
	addr := startFakeServer(t, fakeRedis(false))
	res, err := ScanDB(context.Background(), addr, "redis", nil, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "7.2.4" || res.AuthRequired {
		t.Fatalf("unexpected redis result: %+v", res)
	}
}

func TestScanRedisAuthRequiredAndSucceeds(t *testing.T) {
	addr := startFakeServer(t, fakeRedis(true))
	if _, err := ScanDB(context.Background(), addr, "redis", nil, *DefaultConfig().Normalized()); err != nil {
		t.Fatal(err)
	}
	res, err := ScanDB(context.Background(), addr, "redis",
		&Credential{Password: "pw"}, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "7.2.4" || !res.AuthRequired {
		t.Fatalf("unexpected redis result: %+v", res)
	}
}

func TestScanRedisBadCredentials(t *testing.T) {
	addr := startFakeServer(t, fakeRedis(true))
	if _, err := ScanDB(context.Background(), addr, "redis",
		&Credential{Password: "wrong"}, *DefaultConfig().Normalized()); err == nil {
		t.Fatal("expected auth failure")
	}
}

func fakeRedis(requireAuth bool) func(net.Conn) {
	authed := false
	return func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if !strings.HasPrefix(line, "*") {
				conn.Write([]byte("-ERR unknown command\r\n"))
				continue
			}
			var n int
			fmt.Sscanf(strings.TrimSpace(line), "*%d", &n)
			args := make([]string, 0, n)
			for i := 0; i < n; i++ {
				lenLine, err := br.ReadString('\n')
				if err != nil {
					return
				}
				var size int
				fmt.Sscanf(strings.TrimSpace(lenLine), "$%d", &size)
				buf := make([]byte, size+2)
				if _, err := io.ReadFull(br, buf); err != nil {
					return
				}
				args = append(args, string(buf[:size]))
			}
			cmd := strings.ToUpper(args[0])
			switch cmd {
			case "PING":
				if requireAuth && !authed {
					conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				} else {
					conn.Write([]byte("+PONG\r\n"))
				}
			case "AUTH":
				if len(args) >= 2 && args[len(args)-1] == "pw" {
					authed = true
					conn.Write([]byte("+OK\r\n"))
				} else {
					conn.Write([]byte("-ERR invalid password\r\n"))
				}
			case "INFO":
				if requireAuth && !authed {
					conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
					continue
				}
				body := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n"
				fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(body), body)
			default:
				conn.Write([]byte("-ERR unknown command\r\n"))
			}
		}
	}
}

func startFakeServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

func TestParseVersions(t *testing.T) {
	if got := parseRedisVersion("# Server\r\nredis_version:7.2.4\r\n"); got != "7.2.4" {
		t.Fatalf("parseRedisVersion = %q", got)
	}
	if got := parsePostgreSQLVersion("PostgreSQL 15.3 (Ubuntu 15.3-1.pgdg22.04+1) on x86_64-pc-linux-gnu"); got != "15.3" {
		t.Fatalf("parsePostgreSQLVersion = %q", got)
	}
	if got := parsePostgreSQLVersion("PostgreSQL 16.2"); got != "16.2" {
		t.Fatalf("parsePostgreSQLVersion = %q", got)
	}
	if got := cleanVersion("8.0.36-community"); got != "8.0.36" {
		t.Fatalf("cleanVersion = %q", got)
	}
}
