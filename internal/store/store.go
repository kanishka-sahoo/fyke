package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db          *sql.DB
	sealer      *cryptokit.Sealer
	dataDir     string
	artifactDir string
	writeMu     sync.Mutex
}
type Query struct {
	Limit, Offset                                    int
	Protocol, Type, Outcome, Source, Session, Search string
	Since, Until                                     time.Time
}
type EventRecord struct {
	model.Event
	EvidenceRefs []EvidenceRef `json:"evidence_refs,omitempty"`
}
type EvidenceRef struct {
	ID, Kind, ContentType, Filename, SHA256 string
	Size                                    int64
}
type Overview struct {
	Events24h    int64            `json:"events_24h"`
	Sessions24h  int64            `json:"sessions_24h"`
	Sources24h   int64            `json:"sources_24h"`
	Artifacts24h int64            `json:"artifacts_24h"`
	Sensors      []SensorHealth   `json:"sensors"`
	Protocols    map[string]int64 `json:"protocols"`
}
type SensorHealth struct {
	ID             string    `json:"id"`
	LastSeen       time.Time `json:"last_seen"`
	Status         string    `json:"status"`
	LastSequence   uint64    `json:"last_sequence"`
	RecordedStatus string    `json:"-"`
}

func Open(dataDir string, sealer *cryptokit.Sealer) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "artifacts"), 0700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "fyke.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	s := &Store{db: db, sealer: sealer, dataDir: dataDir, artifactDir: filepath.Join(dataDir, "artifacts")}
	if err = s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) migrate(ctx context.Context) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, schema_version INTEGER NOT NULL, sensor_id TEXT NOT NULL, session_id TEXT NOT NULL, sequence INTEGER NOT NULL, source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER, protocol TEXT NOT NULL, event_type TEXT NOT NULL, outcome TEXT, persona TEXT, attributes_json TEXT NOT NULL, protocol_json TEXT NOT NULL, UNIQUE(sensor_id,session_id,sequence))`,
		`CREATE INDEX IF NOT EXISTS events_time ON events(timestamp DESC)`, `CREATE INDEX IF NOT EXISTS events_source ON events(source_ip,timestamp DESC)`, `CREATE INDEX IF NOT EXISTS events_session ON events(session_id,sequence)`, `CREATE INDEX IF NOT EXISTS events_kind ON events(protocol,event_type,outcome,timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,kind TEXT NOT NULL,content_type TEXT,filename TEXT,sha256 TEXT NOT NULL,size INTEGER NOT NULL,path TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS evidence_event ON evidence(event_id)`, `CREATE INDEX IF NOT EXISTS evidence_hash ON evidence(sha256)`,
		`CREATE TABLE IF NOT EXISTS sensors(id TEXT PRIMARY KEY,last_seen TEXT NOT NULL,last_session TEXT,last_sequence INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'healthy')`,
		`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value_json TEXT NOT NULL,updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,action TEXT NOT NULL,remote_ip TEXT,details_json TEXT NOT NULL)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS event_search USING fts5(id UNINDEXED,source_ip,protocol,event_type,outcome,content)`,
		`INSERT OR IGNORE INTO migrations(version,applied_at) VALUES(1,datetime('now'))`}
	for _, q := range stmts {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			return fmt.Errorf("migration: %w", e)
		}
	}
	return tx.Commit()
}

func (s *Store) Insert(ctx context.Context, e model.Event) error {
	if err := e.Normalize(time.Now()); err != nil {
		return err
	}
	a, _ := json.Marshal(e.Attributes)
	p, _ := json.Marshal(e.ProtocolData)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var createdEvidence []string
	committed := false
	defer func() {
		if !committed {
			for _, path := range createdEvidence {
				_ = os.Remove(path)
			}
		}
	}()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Schema, e.SensorID, e.SessionID, e.Sequence, e.Source.IP, e.Source.Port, e.Destination.IP, e.Destination.Port, e.Protocol, e.Type, e.Outcome, e.Persona, string(a), string(p))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		err = tx.Commit()
		committed = err == nil
		return err
	}
	search := plainSearch(e.Attributes) + " " + plainSearch(e.ProtocolData)
	if _, err = tx.ExecContext(ctx, `INSERT INTO event_search(id,source_ip,protocol,event_type,outcome,content) VALUES(?,?,?,?,?,?)`, e.ID, e.Source.IP, e.Protocol, e.Type, e.Outcome, search); err != nil {
		return err
	}
	for _, ev := range e.Evidence {
		sealed, er := s.sealer.Seal(ev.Data)
		if er != nil {
			return er
		}
		sum := sha256.Sum256(ev.Data)
		hash := hex.EncodeToString(sum[:])
		id := model.NewUUIDv7(time.Now())
		rel := filepath.Join(hash[:2], hash+"-"+id+".age")
		full := filepath.Join(s.artifactDir, rel)
		if er = os.MkdirAll(filepath.Dir(full), 0700); er != nil {
			return er
		}
		if er = os.WriteFile(full, sealed, 0600); er != nil {
			return er
		}
		createdEvidence = append(createdEvidence, full)
		name := ""
		if ev.Filename != "" {
			name = filepath.Base(strings.ReplaceAll(ev.Filename, "\\", "/"))
		}
		if _, er = tx.ExecContext(ctx, `INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)`, id, e.ID, ev.Kind, ev.ContentType, name, hash, len(ev.Data), rel, e.Timestamp.UTC().Format(time.RFC3339Nano)); er != nil {
			return er
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sensors(id,last_seen,last_session,last_sequence,status) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,last_session=excluded.last_session,last_sequence=MAX(sensors.last_sequence,excluded.last_sequence),status='healthy'`, e.SensorID, e.Timestamp.Format(time.RFC3339Nano), e.SessionID, e.Sequence, "healthy")
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}
func plainSearch(v map[string]any) string {
	var b strings.Builder
	for k, x := range v {
		if sensitiveKey(k) {
			continue
		}
		b.WriteString(k)
		b.WriteByte(' ')
		switch y := x.(type) {
		case string:
			b.WriteString(y)
		case float64:
			fmt.Fprint(&b, y)
		}
	}
	return b.String()
}
func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "password") || strings.Contains(k, "body") || strings.Contains(k, "argument") || strings.Contains(k, "transcript")
}

func (s *Store) List(ctx context.Context, q Query) ([]EventRecord, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, v any) { where = append(where, clause); args = append(args, v) }
	if q.Protocol != "" {
		add("protocol=?", q.Protocol)
	}
	if q.Type != "" {
		add("event_type=?", q.Type)
	}
	if q.Outcome != "" {
		add("outcome=?", q.Outcome)
	}
	if q.Source != "" {
		add("source_ip=?", q.Source)
	}
	if q.Session != "" {
		add("session_id=?", q.Session)
	}
	if !q.Since.IsZero() {
		add("timestamp>=?", q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		add("timestamp<=?", q.Until.UTC().Format(time.RFC3339Nano))
	}
	if q.Search != "" {
		where = append(where, "id IN (SELECT id FROM event_search WHERE event_search MATCH ?)")
		args = append(args, q.Search)
	}
	args = append(args, q.Limit, q.Offset)
	rows, e := s.db.QueryContext(ctx, `SELECT id,timestamp,schema_version,sensor_id,session_id,sequence,source_ip,source_port,destination_ip,destination_port,protocol,event_type,outcome,persona,attributes_json,protocol_json FROM events WHERE `+strings.Join(where, " AND ")+` ORDER BY timestamp DESC LIMIT ? OFFSET ?`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []EventRecord
	for rows.Next() {
		var r EventRecord
		var ts, a, p string
		if e = rows.Scan(&r.ID, &ts, &r.Schema, &r.SensorID, &r.SessionID, &r.Sequence, &r.Source.IP, &r.Source.Port, &r.Destination.IP, &r.Destination.Port, &r.Protocol, &r.Type, &r.Outcome, &r.Persona, &a, &p); e != nil {
			return nil, e
		}
		r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		json.Unmarshal([]byte(a), &r.Attributes)
		json.Unmarshal([]byte(p), &r.ProtocolData)
		refs, er := s.evidenceRefs(ctx, r.ID)
		if er != nil {
			return nil, er
		}
		r.EvidenceRefs = refs
		out = append(out, r)
	}
	return out, rows.Err()
}

// Event returns one normalized event and its encrypted evidence references.
// Evidence bytes remain sealed until the caller explicitly requests a preview
// or download through the artifact endpoints.
func (s *Store) Event(ctx context.Context, id string) (EventRecord, error) {
	var r EventRecord
	var ts, a, p string
	e := s.db.QueryRowContext(ctx, `SELECT id,timestamp,schema_version,sensor_id,session_id,sequence,source_ip,source_port,destination_ip,destination_port,protocol,event_type,outcome,persona,attributes_json,protocol_json FROM events WHERE id=?`, id).Scan(&r.ID, &ts, &r.Schema, &r.SensorID, &r.SessionID, &r.Sequence, &r.Source.IP, &r.Source.Port, &r.Destination.IP, &r.Destination.Port, &r.Protocol, &r.Type, &r.Outcome, &r.Persona, &a, &p)
	if e != nil {
		return r, e
	}
	r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	json.Unmarshal([]byte(a), &r.Attributes)
	json.Unmarshal([]byte(p), &r.ProtocolData)
	r.EvidenceRefs, e = s.evidenceRefs(ctx, r.ID)
	return r, e
}

func (s *Store) evidenceRefs(ctx context.Context, eventID string) ([]EvidenceRef, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,kind,content_type,filename,sha256,size FROM evidence WHERE event_id=? ORDER BY id`, eventID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []EvidenceRef
	for rows.Next() {
		var r EvidenceRef
		if e = rows.Scan(&r.ID, &r.Kind, &r.ContentType, &r.Filename, &r.SHA256, &r.Size); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Evidence(ctx context.Context, id string) (EvidenceRef, []byte, error) {
	var r EvidenceRef
	var rel string
	e := s.db.QueryRowContext(ctx, `SELECT id,kind,content_type,filename,sha256,size,path FROM evidence WHERE id=?`, id).Scan(&r.ID, &r.Kind, &r.ContentType, &r.Filename, &r.SHA256, &r.Size, &rel)
	if e != nil {
		return r, nil, e
	}
	sealed, e := os.ReadFile(filepath.Join(s.artifactDir, rel))
	if e != nil {
		return r, nil, e
	}
	b, e := s.sealer.Open(sealed)
	return r, b, e
}
func (s *Store) Overview(ctx context.Context) (Overview, error) {
	o := Overview{Protocols: map[string]int64{}}
	since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
	queries := []struct {
		dst *int64
		q   string
	}{{&o.Events24h, `SELECT count(*) FROM events WHERE timestamp>=?`}, {&o.Sessions24h, `SELECT count(DISTINCT session_id) FROM events WHERE timestamp>=?`}, {&o.Sources24h, `SELECT count(DISTINCT source_ip) FROM events WHERE timestamp>=?`}, {&o.Artifacts24h, `SELECT count(*) FROM evidence WHERE created_at>=?`}}
	for _, x := range queries {
		if e := s.db.QueryRowContext(ctx, x.q, since).Scan(x.dst); e != nil {
			return o, e
		}
	}
	rows, e := s.db.QueryContext(ctx, `SELECT protocol,count(*) FROM events WHERE timestamp>=? GROUP BY protocol`, since)
	if e != nil {
		return o, e
	}
	for rows.Next() {
		var k string
		var n int64
		rows.Scan(&k, &n)
		o.Protocols[k] = n
	}
	rows.Close()
	o.Sensors, e = s.SensorHealth(ctx, time.Now(), 2*time.Minute)
	return o, e
}

func (s *Store) SensorHealth(ctx context.Context, now time.Time, unhealthyAfter time.Duration) ([]SensorHealth, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,last_seen,status,last_sequence FROM sensors WHERE id <> 'controller' ORDER BY id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []SensorHealth
	for rows.Next() {
		var h SensorHealth
		var t string
		if e = rows.Scan(&h.ID, &t, &h.RecordedStatus, &h.LastSequence); e != nil {
			return nil, e
		}
		h.Status = h.RecordedStatus
		h.LastSeen, _ = time.Parse(time.RFC3339Nano, t)
		if now.Sub(h.LastSeen) > unhealthyAfter {
			h.Status = "unhealthy"
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (s *Store) SetSensorStatus(ctx context.Context, id, status string) error {
	if status != "healthy" && status != "unhealthy" {
		return fmt.Errorf("invalid sensor status %q", status)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, e := s.db.ExecContext(ctx, `UPDATE sensors SET status=? WHERE id=?`, status, id)
	return e
}
func (s *Store) TouchSensor(ctx context.Context, id string, now time.Time) error {
	if id == "" || id == "controller" {
		return fmt.Errorf("invalid sensor id %q", id)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, e := s.db.ExecContext(ctx, `INSERT INTO sensors(id,last_seen,last_session,last_sequence,status) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status='healthy'`, id, now.UTC().Format(time.RFC3339Nano), "", 0, "healthy")
	return e
}
func (s *Store) Audit(ctx context.Context, action, remote string, details any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	b, _ := json.Marshal(details)
	_, e := s.db.ExecContext(ctx, `INSERT INTO audit VALUES(?,?,?,?,?)`, model.NewUUIDv7(time.Now()), time.Now().UTC().Format(time.RFC3339Nano), action, remote, string(b))
	return e
}
func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at`, key, string(b), time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) GetSetting(ctx context.Context, key string, value any) (bool, error) {
	var b string
	if e := s.db.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key=?`, key).Scan(&b); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		return false, e
	}
	if e := json.Unmarshal([]byte(b), value); e != nil {
		return false, fmt.Errorf("decode setting %q: %w", key, e)
	}
	return true, nil
}
func (s *Store) IntegrityCheck(ctx context.Context) error {
	var v string
	if e := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&v); e != nil {
		return e
	}
	if v != "ok" {
		return errors.New(v)
	}
	return nil
}
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) DB() *sql.DB                    { return s.db }
