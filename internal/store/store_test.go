package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/model"
)

func TestInsertDeduplicatesAndSealsEvidence(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	if _, e := cryptokit.GenerateIdentity(id); e != nil {
		t.Fatal(e)
	}
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	event := model.Event{SensorID: "ssh", SessionID: "session", Sequence: 1, Source: model.Endpoint{IP: "192.0.2.4", Port: 1234}, Protocol: "ssh", Type: "command", Outcome: "success", Evidence: []model.Evidence{{Kind: "command.arguments", Data: []byte("very-secret-argument")}}}
	if e = st.Insert(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	if e = st.Insert(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = st.DB().QueryRow(`SELECT count(*) FROM events`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("events=%d err=%v", n, e)
	}
	if e = st.DB().QueryRow(`SELECT count(*) FROM evidence`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("evidence=%d err=%v", n, e)
	}
	filepath.Walk(filepath.Join(root, "data", "artifacts"), func(p string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("very-secret-argument")) {
				t.Fatal("plaintext evidence on disk")
			}
		}
		return nil
	})
	listed, e := st.List(context.Background(), Query{Limit: 10, Source: "192.0.2.4"})
	if e != nil || len(listed) != 1 {
		t.Fatalf("list=%d err=%v", len(listed), e)
	}
}
func TestRetentionDeletesOldTranscriptBeforeMetadata(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	cryptokit.GenerateIdentity(id)
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	event := model.Event{Timestamp: time.Now().AddDate(0, 0, -100), SensorID: "s", SessionID: "x", Sequence: 1, Source: model.Endpoint{IP: "192.0.2.1"}, Protocol: "ssh", Type: "transcript", Evidence: []model.Evidence{{Kind: "transcript", Data: []byte("old")}}}
	if e = st.Insert(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	r, e := st.Prune(context.Background(), RetentionPolicy{MetadataDays: 180, TranscriptDays: 90, PCAPDays: 14, PayloadDays: 30, TotalBytes: 1 << 30})
	if e != nil {
		t.Fatal(e)
	}
	if r.EvidenceDeleted != 1 || r.EventsDeleted != 0 {
		t.Fatalf("unexpected retention: %#v", r)
	}
}
