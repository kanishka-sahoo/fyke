package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
			full := filepath.Join(s.artifactDir, rel)
			diskBytes := n
			if info, statErr := os.Stat(full); statErr == nil {
				diskBytes = info.Size()
			} else if !os.IsNotExist(statErr) {
				rows.Close()
				return out, statErr
			}
			if e = os.Remove(full); e != nil && !os.IsNotExist(e) {
				rows.Close()
				return out, e
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM evidence WHERE id=?`, id); e != nil {
				rows.Close()
				return out, e
			}
			out.EvidenceDeleted++
			out.BytesDeleted += diskBytes
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
	used, e := s.diskUsage()
	if e != nil {
		return e
	}
	if used <= cap {
		return nil
	}
	type evidenceFile struct{ id, rel string }
	rows, e := s.db.QueryContext(ctx, `SELECT id,path FROM evidence ORDER BY CASE kind WHEN 'pcap' THEN 0 WHEN 'artifact.upload' THEN 1 WHEN 'http.body' THEN 2 WHEN 'transcript' THEN 3 ELSE 4 END,created_at`)
	if e != nil {
		return e
	}
	var evidence []evidenceFile
	for rows.Next() {
		var item evidenceFile
		if e = rows.Scan(&item.id, &item.rel); e != nil {
			rows.Close()
			return e
		}
		evidence = append(evidence, item)
	}
	if e = rows.Close(); e != nil {
		return e
	}
	if e = rows.Err(); e != nil {
		return e
	}
	for next := 0; next < len(evidence) && used > cap; {
		for next < len(evidence) && used > cap {
			item := evidence[next]
			next++
			full := filepath.Join(s.artifactDir, item.rel)
			var diskBytes int64
			if info, statErr := os.Stat(full); statErr == nil {
				diskBytes = info.Size()
			} else if !os.IsNotExist(statErr) {
				return statErr
			}
			if e = os.Remove(full); e != nil && !os.IsNotExist(e) {
				return e
			}
			if _, e = s.db.ExecContext(ctx, `DELETE FROM evidence WHERE id=?`, item.id); e != nil {
				return e
			}
			used -= diskBytes
			out.EvidenceDeleted++
			out.BytesDeleted += diskBytes
		}
		if e = s.checkpoint(ctx); e != nil {
			return e
		}
		used, e = s.diskUsage()
		if e != nil {
			return e
		}
	}
	if e != nil || used <= cap {
		return e
	}
	if out.EvidenceDeleted > 0 {
		if e = s.compact(ctx); e != nil {
			return e
		}
		used, e = s.diskUsage()
		if e != nil || used <= cap {
			return e
		}
	}

	// Evidence is always exhausted before metadata. Delete old events in
	// bounded batches and compact SQLite so the on-disk cap is real rather than
	// merely a count of logical row sizes.
	for used > cap {
		ids, listErr := s.oldestEventIDs(ctx, 500)
		if listErr != nil {
			return listErr
		}
		if len(ids) == 0 {
			return fmt.Errorf("retention cap %d bytes is smaller than Fyke's non-event database state (%d bytes used)", cap, used)
		}
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		args := make([]any, len(ids))
		for i := range ids {
			args[i] = ids[i]
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM event_search WHERE id IN (`+placeholders+`)`, args...); e == nil {
			var result interface{ RowsAffected() (int64, error) }
			result, e = tx.ExecContext(ctx, `DELETE FROM events WHERE id IN (`+placeholders+`)`, args...)
			if e == nil {
				var deleted int64
				deleted, e = result.RowsAffected()
				out.EventsDeleted += deleted
			}
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		if e = s.compact(ctx); e != nil {
			return e
		}
		used, e = s.diskUsage()
		if e != nil {
			return e
		}
	}
	return nil
}

func (s *Store) oldestEventIDs(ctx context.Context, limit int) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM events ORDER BY timestamp,id LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) checkpoint(ctx context.Context) error {
	_, e := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return e
}

func (s *Store) compact(ctx context.Context) error {
	if e := s.checkpoint(ctx); e != nil {
		return e
	}
	if _, e := s.db.ExecContext(ctx, `VACUUM`); e != nil {
		return e
	}
	return s.checkpoint(ctx)
}

func (s *Store) diskUsage() (int64, error) {
	var used int64
	e := filepath.Walk(s.dataDir, func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() {
			used += info.Size()
		}
		return nil
	})
	return used, e
}
