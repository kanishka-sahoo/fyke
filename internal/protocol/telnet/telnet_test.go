package telnet

import (
	"bytes"
	"testing"
)

func TestReaderStripsNegotiation(t *testing.T) {
	r := newReader(bytes.NewReader([]byte{iac, will, 1, 'r', 'o', 'o', 't', '\r', '\n'}))
	got, e := r.line(20)
	if e != nil || got != "root" {
		t.Fatalf("got %q err=%v", got, e)
	}
}
func FuzzTelnetLine(f *testing.F) {
	f.Add([]byte{iac, will, 1, 'x', '\n'})
	f.Fuzz(func(t *testing.T, b []byte) { r := newReader(bytes.NewReader(b)); _, _ = r.line(1024) })
}
