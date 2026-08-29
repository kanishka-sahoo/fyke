package cryptokit

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "identity")
	if _, e := GenerateIdentity(p); e != nil {
		t.Fatal(e)
	}
	s, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("hostile secret")
	sealed, e := s.Seal(plain)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("plaintext leaked")
	}
	got, e := s.Open(sealed)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatalf("got %q err=%v", got, e)
	}
}
