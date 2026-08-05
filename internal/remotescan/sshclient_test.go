package remotescan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCollectLinuxPasswordAuth(t *testing.T) {
	srv := newTestSSHServer(t, "hunter2", nil)
	defer srv.Close()

	key := srv.HostPublicKey()
	var putKey []byte
	policy := HostKeyPolicy{
		Get: func(string) ([]byte, error) { return nil, nil },
		Put: func(string, []byte) error { putKey = append(putKey[:0], key...); return nil },
	}
	inv, err := Collect(context.Background(), srv.Addr(), Credential{
		Username: "alice", AuthType: AuthTypePassword, Password: "hunter2",
	}, policy, Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	if inv.OSType != "linux" || inv.OS != "ubuntu" || inv.Version != "24.04" || inv.Arch != "amd64" {
		t.Fatalf("inventory = %+v", inv)
	}
	if inv.Hostname != "testbox" {
		t.Fatalf("hostname = %q", inv.Hostname)
	}
	if len(inv.Assets) != 3 { // os + openssl + curl
		t.Fatalf("assets = %+v", inv.Assets)
	}
	if len(putKey) == 0 {
		t.Fatal("host key was not persisted")
	}
	if !strings.EqualFold(string(putKey), string(key)) {
		t.Fatal("persisted host key differs from server key")
	}
}

func TestCollectHostKeyToFU(t *testing.T) {
	srv := newTestSSHServer(t, "hunter2", nil)
	defer srv.Close()

	serverKey := srv.HostPublicKey()
	stored := serverKey
	policy := HostKeyPolicy{
		Get: func(string) ([]byte, error) { return stored, nil },
		Put: func(string, []byte) error { return nil },
	}
	// Same key: accepted.
	if _, err := Collect(context.Background(), srv.Addr(), Credential{
		Username: "alice", AuthType: AuthTypePassword, Password: "hunter2",
	}, policy, Options{TimeoutSeconds: 5}); err != nil {
		t.Fatalf("same host key should pass: %v", err)
	}
	// Changed key: rejected before any command runs.
	stored = []byte("totally-different-key-bytes")
	_, err := Collect(context.Background(), srv.Addr(), Credential{
		Username: "alice", AuthType: AuthTypePassword, Password: "hunter2",
	}, policy, Options{TimeoutSeconds: 5})
	if err == nil || !strings.Contains(err.Error(), "host key changed") {
		t.Fatalf("changed host key error = %v", err)
	}
}

func TestCollectBadPassword(t *testing.T) {
	srv := newTestSSHServer(t, "hunter2", nil)
	defer srv.Close()

	_, err := Collect(context.Background(), srv.Addr(), Credential{
		Username: "alice", AuthType: AuthTypePassword, Password: "wrong",
	}, HostKeyPolicy{}, Options{TimeoutSeconds: 5})
	if err == nil {
		t.Fatal("bad password must fail")
	}
}

func TestCollectKeyAuth(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestSSHServer(t, "", sshPub)
	defer srv.Close()

	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	inv, err := Collect(context.Background(), srv.Addr(), Credential{
		Username: "bob", AuthType: AuthTypeKey, PrivateKey: keyPEM,
	}, HostKeyPolicy{}, Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS != "ubuntu" {
		t.Fatalf("inventory = %+v", inv)
	}
}

type testSSHServer struct {
	ln       net.Listener
	hostKey  ssh.Signer
	password string
	pubKey   ssh.PublicKey
}

func newTestSSHServer(t *testing.T, password string, pubKey ssh.PublicKey) *testSSHServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if password != "" && string(pass) == password {
				return nil, nil
			}
			return nil, errAuthFailed
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if pubKey != nil && string(key.Marshal()) == string(pubKey.Marshal()) {
				return nil, nil
			}
			return nil, errAuthFailed
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{ln: ln, hostKey: hostSigner, password: password, pubKey: pubKey}
	go s.serve(cfg)
	t.Cleanup(func() { ln.Close() })
	return s
}

var errAuthFailed = &authError{}

type authError struct{}

func (*authError) Error() string { return "authentication failed" }

func (s *testSSHServer) serve(cfg *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go handleSSHConn(conn, cfg)
	}
}

func handleSSHConn(conn net.Conn, cfg *ssh.ServerConfig) {
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		go handleSession(newCh)
	}
}

func handleSession(newCh ssh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			out, errText := commandOutput(payload.Command)
			if errText != "" {
				io.WriteString(ch.Stderr(), errText)
			}
			io.WriteString(ch, out)
			status := uint32(0)
			if errText != "" {
				status = 1
			}
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
			ch.Close()
			return
		case "pty-req":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func commandOutput(cmd string) (string, string) {
	switch {
	case cmd == "uname -s":
		return "Linux\n", ""
	case cmd == "hostname":
		return "testbox\n", ""
	case cmd == "uname -s -r -m":
		return "Linux 6.8.0 x86_64\n", ""
	case cmd == "cat /etc/os-release":
		return "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n", ""
	case strings.Contains(cmd, "dpkg-query"):
		return "openssl\t3.0.13-1ubuntu3\ncurl\t8.5.0-2\n", ""
	default:
		return "", "unknown command"
	}
}

func (s *testSSHServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *testSSHServer) Close() {
	s.ln.Close()
}

func (s *testSSHServer) HostPublicKey() []byte {
	return s.hostKey.PublicKey().Marshal()
}
