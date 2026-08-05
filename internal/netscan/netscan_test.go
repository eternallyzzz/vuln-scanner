package netscan

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestExpandTargets(t *testing.T) {
	got, err := ExpandTargets([]string{"127.0.0.1", "192.168.1.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandTargets = %v, want %v", got, want)
	}
}

func TestExpandTargetsRejectsIPv6(t *testing.T) {
	if _, err := ExpandTargets([]string{"::1"}); err == nil {
		t.Fatal("IPv6 target must be rejected")
	}
	if _, err := ExpandTargets([]string{"2001:db8::/32"}); err == nil {
		t.Fatal("IPv6 CIDR must be rejected")
	}
	if _, err := ExpandTargets([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid target must be rejected")
	}
}

func TestGuessOS(t *testing.T) {
	cases := []struct {
		ports []int
		want  string
	}{
		{[]int{445}, "windows"},
		{[]int{139, 80}, "windows"},
		{[]int{22}, "linux"},
		{[]int{80, 443}, "unknown"},
		{nil, "unknown"},
	}
	for _, c := range cases {
		if got := GuessOS(c.ports); got != c.want {
			t.Errorf("GuessOS(%v) = %q, want %q", c.ports, got, c.want)
		}
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		port     int
		banner   string
		wantProd string
		wantVer  string
	}{
		{22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "openssh", "8.9p1"},
		{22, "SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"},
		{80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n", "nginx", "1.24.0"},
		{8080, "HTTP/1.0 400 Bad Request\r\nServer: Apache/2.4.57 (Ubuntu)\r\n", "apache", "2.4.57"},
		{21, "220 (vsFTPd 3.0.5)", "vsftpd", "3.0.5"},
		{25, "220 mx ESMTP Exim 4.96", "exim", "4.96"},
		{25, "220 mx ESMTP Postfix", "postfix", ""},
		{3306, "\x0a\x00\x00\x00\xff", "", ""},
	}
	for _, c := range cases {
		prod, ver := ParseBanner(c.port, c.banner)
		if prod != c.wantProd || ver != c.wantVer {
			t.Errorf("ParseBanner(%d, %q) = (%q,%q), want (%q,%q)",
				c.port, c.banner, prod, ver, c.wantProd, c.wantVer)
		}
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(22) != "ssh" || ServiceName(3306) != "mysql" || ServiceName(9999) != "tcp-9999" {
		t.Fatal("service name mapping broken")
	}
}

func TestScanLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener available")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	hosts, err := Scan(context.Background(), Config{
		Targets: []string{"127.0.0.1"},
		Ports:   []int{port},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != "127.0.0.1" || len(hosts[0].Services) != 1 {
		t.Fatalf("Scan loopback = %+v, want one host with one service", hosts)
	}
}

func TestLocalNonLoopbackExcludesSelf(t *testing.T) {
	ips := LocalNonLoopbackIPs()
	sort.Strings(ips)
	for _, ip := range ips {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).IsLoopback() {
			t.Fatalf("LocalNonLoopbackIPs returned loopback/invalid IP %q", ip)
		}
	}
}
