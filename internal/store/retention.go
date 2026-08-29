package store

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

type RetentionPolicy struct {
	MetadataDays, TranscriptDays, PCAPDays, PayloadDays int
	TotalBytes                                          int64
}
type RetentionResult struct {
	EvidenceDeleted, EventsDeleted int64
	BytesDeleted                   int64
}

func (s *Store) Prune(ctx context.Context, p RetentionPolicy) (RetentionResult, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var out RetentionResult
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	types := []struct {
		kind string
		days int
	}{{"pcap", p.PCAPDays}, {"artifact.upload", p.PayloadDays}, {"http.body", p.PayloadDays}, {"transcript", p.TranscriptDays}}
	for _, x := range types {
		cut := now.AddDate(0, 0, -x.days).Format(time.RFC3339Nano)
		rows, e := tx.QueryContext(ctx, `SELECT id,path,size FROM evidence WHERE kind=? AND created_at<?`, x.kind, cut)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var id, rel string
			var n int64
			if e = rows.Scan(&id, &rel, &n); e != nil {
				rows.Close()
				return out, e
			}
			if e = os.Remove(filepath.Join(s.artifactDir, rel)); e != nil && !os.IsNotExist(e) {
				rows.Close()
				return out, e
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM evidence WHERE id=?`, id); e != nil {
				rows.Close()
				return out, e
			}
			out.EvidenceDeleted++
			out.BytesDeleted += n
		}
		rows.Close()
	}
	cut := now.AddDate(0, 0, -p.MetadataDays).Format(time.RFC3339Nano)
	if _, e = tx.ExecContext(ctx, `DELETE FROM event_search WHERE id IN (SELECT id FROM events WHERE timestamp<?)`, cut); e != nil {
		return out, e
	}
	res, e := tx.ExecContext(ctx, `DELETE FROM events WHERE timestamp<?`, cut)
	if e != nil {
		return out, e
	}
	out.EventsDeleted, _ = res.RowsAffected()
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, s.enforceCap(ctx, p.TotalBytes, &out)
}
func (s *Store) enforceCap(ctx context.Context, cap int64, out *RetentionResult) error {
	if cap <= 0 {
		return nil
	}
	var used int64
	filepath.Walk(s.artifactDir, func(_ string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() {
			used += i.Size()
		}
		return nil
	})
	if used <= cap {
		return nil
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id,path,size FROM evidence ORDER BY CASE kind WHEN 'pcap' THEN 0 WHEN 'artifact.upload' THEN 1 WHEN 'transcript' THEN 2 ELSE 3 END,created_at`)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		if used <= cap {
			break
		}
		var id, rel string
		var n int64
		if e = rows.Scan(&id, &rel, &n); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join(s.artifactDir, rel)); e != nil && !os.IsNotExist(e) {
			return e
		}
		if _, e = s.db.ExecContext(ctx, `DELETE FROM evidence WHERE id=?`, id); e != nil {
			return e
		}
		used -= n
		out.EvidenceDeleted++
		out.BytesDeleted += n
	}
	return rows.Err()
}
