package cryptokit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

type Sealer struct {
	identity  *age.X25519Identity
	recipient age.Recipient
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
	return &Sealer{identity: id, recipient: id.Recipient()}, nil
}
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
