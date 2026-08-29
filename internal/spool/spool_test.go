package spool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedReplayAndAck(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	secret := []byte("password-that-must-not-appear-on-disk")
	if e = s.Put("event-1", secret); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(dir)
	for _, x := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, x.Name()))
		if bytes.Contains(b, secret) {
			t.Fatalf("plaintext in %s", x.Name())
		}
	}
	records, e := s.List()
	if e != nil || len(records) != 1 || !bytes.Equal(records[0].Data, secret) {
		t.Fatalf("replay=%#v err=%v", records, e)
	}
	if e = s.Ack("event-1"); e != nil {
		t.Fatal(e)
	}
	records, _ = s.List()
	if len(records) != 0 {
		t.Fatal("acknowledged record retained")
	}
}
func TestFullSpoolBackpressures(t *testing.T) {
	s, e := Open(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Put("large", make([]byte, 1<<20)); e != ErrFull {
		t.Fatalf("got %v, want ErrFull", e)
	}
}
