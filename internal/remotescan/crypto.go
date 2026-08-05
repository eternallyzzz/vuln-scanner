package remotescan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Cipher encrypts remote scan credentials at rest with AES-256-GCM. Secrets
// are base64(nonce || ciphertext) and never appear in logs or API responses.
type Cipher struct {
	gcm cipher.AEAD
}

// NewCipher builds the credential cipher from a 32-byte master key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, errors.New("remote scan master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{gcm: gcm}, nil
}

// Encrypt seals plaintext and returns a base64 string. Empty input yields
// an empty string.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a base64 secret. Empty input yields nil.
func (c *Cipher) Decrypt(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	if len(raw) < c.gcm.NonceSize() {
		return nil, errors.New("secret too short")
	}
	nonce, sealed := raw[:c.gcm.NonceSize()], raw[c.gcm.NonceSize():]
	plain, err := c.gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return plain, nil
}
