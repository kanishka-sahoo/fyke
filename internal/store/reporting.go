package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// ForEachSnapshot visits every event matching q that existed when the call
// began. It pages by SQLite rowid so concurrent inserts cannot extend the
// export and retention deletions cannot cause offset-based skips.
func (s *Store) ForEachSnapshot(ctx context.Context, q Query, fn func(EventRecord) error) (int64, error) {
	var highWater int64
	if e := s.db.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM events`).Scan(&highWater); e != nil {
		return 0, e
	}
	if highWater == 0 {
		return 0, nil
	}
	where, baseArgs := eventWhere(q)
	var cursor, visited int64
	const pageSize = 500
	for cursor < highWater {
		args := append(append([]any(nil), baseArgs...), cursor, highWater, pageSize)
		rows, e := s.db.QueryContext(ctx, `SELECT rowid,id,timestamp,schema_version,sensor_id,session_id,sequence,source_ip,source_port,destination_ip,destination_port,protocol,event_type,outcome,persona,attributes_json,protocol_json FROM events WHERE `+where+` AND rowid>? AND rowid<=? ORDER BY rowid LIMIT ?`, args...)
		if e != nil {
			return visited, e
		}
		var page []struct {
			rowid  int64
			record EventRecord
		}
		for rows.Next() {
			var item struct {
				rowid  int64
				record EventRecord
			}
			var ts, attributes, protocol string
			r := &item.record
			if e = rows.Scan(&item.rowid, &r.ID, &ts, &r.Schema, &r.SensorID, &r.SessionID, &r.Sequence, &r.Source.IP, &r.Source.Port, &r.Destination.IP, &r.Destination.Port, &r.Protocol, &r.Type, &r.Outcome, &r.Persona, &attributes, &protocol); e != nil {
				rows.Close()
				return visited, e
			}
			r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
			_ = json.Unmarshal([]byte(attributes), &r.Attributes)
			_ = json.Unmarshal([]byte(protocol), &r.ProtocolData)
			page = append(page, item)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return visited, e
		}
		if e = rows.Close(); e != nil {
			return visited, e
		}
		if len(page) == 0 {
			break
		}
		for _, item := range page {
			cursor = item.rowid
			item.record.EvidenceRefs, e = s.evidenceRefs(ctx, item.record.ID)
			if e != nil {
				return visited, e
			}
			if e = fn(item.record); e != nil {
				return visited, e
			}
			visited++
		}
	}
	return visited, nil
}

type SessionSummary struct {
	SessionID string `json:"session_id"`
	StartedAt string `json:"started_at"`
	LastSeen  string `json:"last_seen"`
	SourceIP  string `json:"source_ip"`
	Protocol  string `json:"protocol"`
	Events    int64  `json:"events"`
}

func (s *Store) Sessions(ctx context.Context, limit, offset int) ([]SessionSummary, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT session_id) FROM events`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT session_id,min(timestamp),max(timestamp),COALESCE(source_ip,''),protocol,count(*) FROM events GROUP BY session_id ORDER BY max(timestamp) DESC LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []SessionSummary
	for rows.Next() {
		var v SessionSummary
		if e = rows.Scan(&v.SessionID, &v.StartedAt, &v.LastSeen, &v.SourceIP, &v.Protocol, &v.Events); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

type SourceSummary struct {
	SourceIP  string `json:"source_ip"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Events    int64  `json:"events"`
	Sessions  int64  `json:"sessions"`
	Label     string `json:"label,omitempty"`
	Country   string `json:"country,omitempty"`
	ASN       string `json:"asn,omitempty"`
	Ignored   bool   `json:"ignored"`
}

func (s *Store) Sources(ctx context.Context, limit, offset int) ([]SourceSummary, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT source_ip) FROM events WHERE source_ip<>''`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT events.source_ip,min(events.timestamp),max(events.timestamp),count(*),count(DISTINCT events.session_id),COALESCE(source_context.label,''),COALESCE(source_context.country,''),COALESCE(source_context.asn,''),COALESCE(source_context.ignored,0) FROM events LEFT JOIN source_context ON source_context.source_ip=events.source_ip WHERE events.source_ip<>'' GROUP BY events.source_ip ORDER BY max(events.timestamp) DESC LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []SourceSummary
	for rows.Next() {
		var v SourceSummary
		if e = rows.Scan(&v.SourceIP, &v.FirstSeen, &v.LastSeen, &v.Events, &v.Sessions, &v.Label, &v.Country, &v.ASN, &v.Ignored); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

type ArtifactRecord struct {
	EvidenceRef
	EventID   string `json:"event_id"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) Artifact(ctx context.Context, id string) (ArtifactRecord, error) {
	var v ArtifactRecord
	e := s.db.QueryRowContext(ctx, `SELECT id,event_id,kind,content_type,filename,sha256,size,created_at FROM evidence WHERE id=?`, id).Scan(&v.ID, &v.EventID, &v.Kind, &v.ContentType, &v.Filename, &v.SHA256, &v.Size, &v.CreatedAt)
	return v, e
}

func (s *Store) Artifacts(ctx context.Context, limit, offset int, hash string) ([]ArtifactRecord, int64, error) {
	where, args := "1=1", []any{}
	if hash != "" {
		where, args = "sha256=?", append(args, hash)
	}
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM evidence WHERE `+where, args...).Scan(&total); e != nil {
		return nil, 0, e
	}
	pageArgs := append(append([]any(nil), args...), limit, offset)
	rows, e := s.db.QueryContext(ctx, `SELECT id,event_id,kind,content_type,filename,sha256,size,created_at FROM evidence WHERE `+where+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, pageArgs...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []ArtifactRecord
	for rows.Next() {
		var v ArtifactRecord
		if e = rows.Scan(&v.ID, &v.EventID, &v.Kind, &v.ContentType, &v.Filename, &v.SHA256, &v.Size, &v.CreatedAt); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

type AuditRecord struct {
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Action    string         `json:"action"`
	RemoteIP  string         `json:"remote_ip,omitempty"`
	Details   map[string]any `json:"details"`
}

func (s *Store) AuditRecords(ctx context.Context, limit, offset int) ([]AuditRecord, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id,timestamp,action,COALESCE(remote_ip,''),details_json FROM audit ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []AuditRecord
	for rows.Next() {
		var v AuditRecord
		var details string
		if e = rows.Scan(&v.ID, &v.Timestamp, &v.Action, &v.RemoteIP, &details); e != nil {
			return nil, 0, e
		}
		_ = json.Unmarshal([]byte(details), &v.Details)
		out = append(out, v)
	}
	return out, total, rows.Err()
}

type StorageStatus struct {
	TotalBytes    int64            `json:"total_bytes"`
	DatabaseBytes int64            `json:"database_bytes"`
	ArtifactBytes int64            `json:"artifact_bytes"`
	Events        int64            `json:"events"`
	Evidence      int64            `json:"evidence"`
	ByKind        map[string]int64 `json:"by_kind"`
	OldestEvent   string           `json:"oldest_event,omitempty"`
	NewestEvent   string           `json:"newest_event,omitempty"`
}

func (s *Store) StorageStatus(ctx context.Context) (StorageStatus, error) {
	v := StorageStatus{ByKind: map[string]int64{}}
	if e := s.db.QueryRowContext(ctx, `SELECT count(*),COALESCE(min(timestamp),''),COALESCE(max(timestamp),'') FROM events`).Scan(&v.Events, &v.OldestEvent, &v.NewestEvent); e != nil {
		return v, e
	}
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM evidence`).Scan(&v.Evidence); e != nil {
		return v, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT kind,COALESCE(sum(size),0) FROM evidence GROUP BY kind`)
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var kind string
		var size int64
		if e = rows.Scan(&kind, &size); e != nil {
			rows.Close()
			return v, e
		}
		v.ByKind[kind] = size
	}
	if e = rows.Close(); e != nil {
		return v, e
	}
	e = filepath.Walk(s.dataDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		v.TotalBytes += info.Size()
		if filepath.Ext(path) == ".db" || filepath.Ext(path) == ".wal" || filepath.Ext(path) == ".shm" || filepath.Base(path) == "fyke.db-wal" || filepath.Base(path) == "fyke.db-shm" {
			v.DatabaseBytes += info.Size()
		} else if filepath.Dir(path) != s.dataDir {
			v.ArtifactBytes += info.Size()
		}
		return nil
	})
	return v, e
}
