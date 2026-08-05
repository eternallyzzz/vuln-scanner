package remotescan

import "vuln-scanner/internal/collector"

const (
	// AuthTypePassword authenticates with a username/password pair.
	AuthTypePassword = "password"
	// AuthTypeKey authenticates with an SSH private key (optionally
	// protected by a passphrase).
	AuthTypeKey = "key"
)

// Credential is the plaintext view of one remote login. It exists only in
// server memory; storage always holds AES-GCM ciphertext.
type Credential struct {
	ID         int64
	Name       string
	Username   string
	AuthType   string
	Password   string
	PrivateKey string
	Passphrase string
}

// Inventory is the read-only result of one SSH collection pass. Assets use
// the same formats as the local collectors (os/deb/rpm/win/hotfix/brew) so
// the existing matcher consumes them unchanged.
type Inventory struct {
	Hostname string
	OSType   string // linux | darwin | windows
	OS       string // distro/product name, e.g. ubuntu, centos, windows, macos
	Version  string
	Arch     string
	Kernel   string
	Assets   []collector.Asset
}

// Options bounds one SSH collection pass.
type Options struct {
	TimeoutSeconds int
}

// HostKeyPolicy implements trust-on-first-use host key verification.
// Get returns the previously stored marshaled public key (nil when unknown);
// Put persists a key after a successful authenticated collection.
type HostKeyPolicy struct {
	Get func(address string) ([]byte, error)
	Put func(address string, key []byte) error
}
