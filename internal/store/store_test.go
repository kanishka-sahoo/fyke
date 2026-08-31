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
	got, e := st.Event(context.Background(), listed[0].ID)
	if e != nil || got.ID != listed[0].ID || len(got.EvidenceRefs) != 1 {
		t.Fatalf("event=%#v err=%v", got, e)
	}
	total, e := st.Count(context.Background(), Query{Source: "192.0.2.4", Type: "command"})
	if e != nil || total != 1 {
		t.Fatalf("count=%d err=%v", total, e)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	cryptokit.GenerateIdentity(id)
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	want := map[string]any{"enabled": true, "threshold": float64(12)}
	if e = st.SetSetting(context.Background(), "test", want); e != nil {
		t.Fatal(e)
	}
	var got map[string]any
	found, e := st.GetSetting(context.Background(), "test", &got)
	if e != nil || !found || got["enabled"] != true || got["threshold"] != float64(12) {
		t.Fatalf("GetSetting() = %#v, %t, %v", got, found, e)
	}
}

func TestTouchSensorRefreshesHealthWithoutCreatingEvent(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	cryptokit.GenerateIdentity(id)
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	now := time.Now().UTC()
	if e = st.TouchSensor(context.Background(), "ssh", now); e != nil {
		t.Fatal(e)
	}
	health, e := st.SensorHealth(context.Background(), now.Add(time.Minute), 2*time.Minute)
	if e != nil || len(health) != 1 || health[0].Status != "healthy" {
		t.Fatalf("health = %#v, %v", health, e)
	}
	var events int
	if e = st.DB().QueryRow(`SELECT count(*) FROM events`).Scan(&events); e != nil || events != 0 {
		t.Fatalf("heartbeat created %d events: %v", events, e)
	}
}

func TestRetentionCapIncludesDatabaseAndEvictsEvidenceFirst(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	cryptokit.GenerateIdentity(id)
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ctx := context.Background()
	for i := 1; i <= 300; i++ {
		event := model.Event{SensorID: "ssh", SessionID: "cap", Sequence: uint64(i), Protocol: "ssh", Type: "command", Attributes: map[string]any{"payload": string(bytes.Repeat([]byte{'x'}, 8192))}}
		if i == 1 {
			event.Evidence = []model.Evidence{{Kind: "transcript", Data: bytes.Repeat([]byte{'s'}, 256<<10)}}
		}
		if e = st.Insert(ctx, event); e != nil {
			t.Fatal(e)
		}
	}
	if e = st.checkpoint(ctx); e != nil {
		t.Fatal(e)
	}
	before, e := st.diskUsage()
	if e != nil || before <= 1<<20 {
		t.Fatalf("test fixture uses %d bytes: %v", before, e)
	}
	result, e := st.Prune(ctx, RetentionPolicy{MetadataDays: 365, TranscriptDays: 365, PCAPDays: 365, PayloadDays: 365, TotalBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	after, e := st.diskUsage()
	if e != nil {
		t.Fatal(e)
	}
	if after > 1<<20 {
		t.Fatalf("disk usage after prune = %d, want <= %d", after, 1<<20)
	}
	if result.EvidenceDeleted != 1 || result.EventsDeleted == 0 {
		t.Fatalf("unexpected retention result: %#v", result)
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

func TestForEachSnapshotHasNoHiddenLimitAndStableHighWater(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	cryptokit.GenerateIdentity(id)
	seal, _ := cryptokit.Load(id)
	st, e := Open(filepath.Join(root, "data"), seal)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ctx := context.Background()
	for i := 1; i <= 1205; i++ {
		event := model.Event{SensorID: "ssh", SessionID: "bulk", Sequence: uint64(i), Protocol: "ssh", Type: "command"}
		if e = st.Insert(ctx, event); e != nil {
			t.Fatal(e)
		}
	}
	seen := 0
	count, e := st.ForEachSnapshot(ctx, Query{}, func(EventRecord) error {
		seen++
		if seen == 1 {
			return st.Insert(ctx, model.Event{SensorID: "ssh", SessionID: "later", Sequence: 1, Protocol: "ssh", Type: "command"})
		}
		return nil
	})
	if e != nil || count != 1205 || seen != 1205 {
		t.Fatalf("snapshot count=%d seen=%d error=%v", count, seen, e)
	}
	total, e := st.Count(ctx, Query{})
	if e != nil || total != 1206 {
		t.Fatalf("database count=%d error=%v", total, e)
	}
}
