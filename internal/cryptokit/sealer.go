package cryptokit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

type Sealer struct {
	identity       *age.X25519Identity
	recipient      age.Recipient
	correlationKey [32]byte
}

func GenerateIdentity(path string) (string, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err = os.WriteFile(path, []byte(id.String()+"\n"), 0600); err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}
func Load(path string) (*Sealer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("parse controller identity: %w", err)
	}
	key := sha256.Sum256([]byte("fyke evidence correlation v1\x00" + id.String()))
	return &Sealer{identity: id, recipient: id.Recipient(), correlationKey: key}, nil
}

// CorrelationToken creates a keyed, domain-separated equality token. It is
// suitable for correlating repeated secrets without storing an ordinary hash
// that could be attacked using only a copied database.
func (s *Sealer) CorrelationToken(domain string, value []byte) string {
	h := hmac.New(sha256.New, s.correlationKey[:])
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Sealer) Recipient() string { return s.identity.Recipient().String() }
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, s.recipient)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(plaintext); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func (s *Sealer) Open(ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), s.identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
func SealTo(recipient string, plaintext []byte) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(plaintext); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
