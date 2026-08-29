package httpdecoy

import (
	"bytes"
	"io"
	"testing"
)

func TestRecordingReaderIsBounded(t *testing.T) {
	r := &recordingReader{r: bytes.NewReader([]byte("0123456789")), max: 4}
	b, _ := io.ReadAll(r)
	if string(b) != "0123456789" {
		t.Fatal("wrapped reader changed input")
	}
	if got := string(r.take()); got != "0123" {
		t.Fatalf("capture=%q", got)
	}
}
