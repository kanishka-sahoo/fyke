package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/model"
)

type Observable struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type SourceContext struct {
	SourceIP  string `json:"source_ip"`
	Label     string `json:"label,omitempty"`
	Ignored   bool   `json:"ignored"`
	Country   string `json:"country,omitempty"`
	ASN       string `json:"asn,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func (s *Store) SetSourceContext(ctx context.Context, value SourceContext) error {
	if _, e := netip.ParseAddr(value.SourceIP); e != nil || len(value.Label) > 256 || len(value.Country) > 128 || len(value.ASN) > 128 {
		return fmt.Errorf("invalid source context")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, e := s.db.ExecContext(ctx, `INSERT INTO source_context(source_ip,label,ignored,country,asn,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(source_ip) DO UPDATE SET label=excluded.label,ignored=excluded.ignored,country=excluded.country,asn=excluded.asn,updated_at=excluded.updated_at`, value.SourceIP, value.Label, value.Ignored, value.Country, value.ASN, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}

func (s *Store) SourceContext(ctx context.Context, source string) (SourceContext, error) {
	var v SourceContext
	e := s.db.QueryRowContext(ctx, `SELECT source_ip,label,ignored,country,asn,updated_at FROM source_context WHERE source_ip=?`, source).Scan(&v.SourceIP, &v.Label, &v.Ignored, &v.Country, &v.ASN, &v.UpdatedAt)
	return v, e
}

func (s *Store) SourceIgnored(ctx context.Context, source string) bool {
	var ignored bool
	_ = s.db.QueryRowContext(ctx, `SELECT ignored FROM source_context WHERE source_ip=?`, source).Scan(&ignored)
	return ignored
}

func extractObservables(event model.Event) []Observable {
	seen := map[string]bool{}
	var out []Observable
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		key := kind + "\x00" + value
		if kind == "" || value == "" || len(value) > 4096 || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Observable{Kind: kind, Value: value})
	}
	add("source.ip", event.Source.IP)
	if event.Attributes != nil {
		if value, ok := event.Attributes["username"].(string); ok {
			add("auth.username", value)
		}
		if value, ok := event.Attributes["fingerprint"].(string); ok {
			add("ssh.fingerprint", value)
		}
		if value, ok := event.Attributes["command"].(string); ok {
			add("command.name", value)
		}
		if value, ok := event.Attributes["http.host"].(string); ok {
			add("http.host", value)
		}
		if value, ok := event.Attributes["url.path"].(string); ok {
			add("url.path", value)
		}
		if values, ok := event.Attributes["urls"].([]string); ok {
			for _, value := range values {
				add("url", value)
			}
		} else if values, ok := event.Attributes["urls"].([]any); ok {
			for _, raw := range values {
				if value, ok := raw.(string); ok {
					add("url", value)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Value < out[j].Value
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func (s *Store) Observables(ctx context.Context, eventID string) ([]Observable, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT kind,value FROM observables WHERE event_id=? ORDER BY kind,value`, eventID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Observable
	for rows.Next() {
		var value Observable
		if e = rows.Scan(&value.Kind, &value.Value); e != nil {
			return nil, e
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *Store) ObservableSeenBefore(ctx context.Context, kind, value, eventID string) (bool, error) {
	var exists int
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM observables WHERE kind=? AND value=? AND event_id<>?)`, kind, value, eventID).Scan(&exists)
	return exists == 1, e
}

func (s *Store) PivotEvents(ctx context.Context, kind, value string, limit, offset int) ([]EventRecord, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM observables WHERE kind=? AND value=?`, kind, value).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT event_id FROM observables WHERE kind=? AND value=? ORDER BY created_at DESC LIMIT ? OFFSET ?`, kind, value, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, 0, e
		}
		ids = append(ids, id)
	}
	if e = rows.Close(); e != nil {
		return nil, 0, e
	}
	var out []EventRecord
	for _, id := range ids {
		event, readErr := s.Event(ctx, id)
		if readErr != nil {
			return nil, 0, readErr
		}
		out = append(out, event)
	}
	return out, total, nil
}

func (s *Store) SecretReuse(ctx context.Context, eventID string) (string, int64, error) {
	var token string
	var count int64
	e := s.db.QueryRowContext(ctx, `SELECT current.token,count(DISTINCT other.event_id) FROM evidence_correlations current JOIN evidence_correlations other ON other.kind=current.kind AND other.token=current.token WHERE current.event_id=? GROUP BY current.token`, eventID).Scan(&token, &count)
	return token, count, e
}

func (s *Store) SourceProtocolCount(ctx context.Context, source string, since time.Time) (int64, error) {
	var count int64
	e := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT protocol) FROM events WHERE source_ip=? AND timestamp>=?`, source, since.UTC().Format(time.RFC3339Nano)).Scan(&count)
	return count, e
}

func (s *Store) HTTPEnumerationStats(ctx context.Context, source string, since time.Time) (int64, int64, error) {
	var requests, paths int64
	e := s.db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT json_extract(attributes_json,'$."url.path"')) FROM events WHERE source_ip=? AND event_type='http.request' AND timestamp>=?`, source, since.UTC().Format(time.RFC3339Nano)).Scan(&requests, &paths)
	return requests, paths, e
}

type Finding struct {
	ID          string       `json:"id"`
	Rule        string       `json:"rule"`
	RuleVersion int          `json:"rule_version"`
	Fingerprint string       `json:"-"`
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Severity    string       `json:"severity"`
	Status      string       `json:"status"`
	SourceIP    string       `json:"source_ip,omitempty"`
	FirstSeen   string       `json:"first_seen"`
	LastSeen    string       `json:"last_seen"`
	EventCount  int64        `json:"event_count"`
	Observables []Observable `json:"observables"`
	UpdatedAt   string       `json:"updated_at"`
}

type FindingInput struct {
	Rule, Fingerprint, Title, Summary, Severity, SourceIP string
	RuleVersion                                           int
	EventID                                               string
	OccurredAt                                            time.Time
	Observables                                           []Observable
}

func (s *Store) UpsertFinding(ctx context.Context, input FindingInput) (Finding, bool, error) {
	if input.Rule == "" || input.Fingerprint == "" || input.EventID == "" {
		return Finding{}, false, fmt.Errorf("finding rule, fingerprint, and event are required")
	}
	if input.RuleVersion < 1 {
		input.RuleVersion = 1
	}
	if input.OccurredAt.IsZero() {
		input.OccurredAt = time.Now().UTC()
	}
	observables, _ := json.Marshal(input.Observables)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seen := input.OccurredAt.UTC().Format(time.RFC3339Nano)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Finding{}, false, e
	}
	defer tx.Rollback()
	id := model.NewUUIDv7(time.Now())
	created := false
	result, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO findings(id,rule,rule_version,fingerprint,title,summary,severity,status,source_ip,first_seen,last_seen,event_count,observables_json,updated_at) VALUES(?,?,?,?,?,?,?,'open',?,?,?,0,?,?)`, id, input.Rule, input.RuleVersion, input.Fingerprint, input.Title, input.Summary, input.Severity, input.SourceIP, seen, seen, string(observables), now)
	if e != nil {
		return Finding{}, false, e
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		created = true
	} else if e = tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE rule=? AND fingerprint=?`, input.Rule, input.Fingerprint).Scan(&id); e != nil {
		return Finding{}, false, e
	}
	link, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_events(finding_id,event_id) VALUES(?,?)`, id, input.EventID)
	if e != nil {
		return Finding{}, false, e
	}
	added, _ := link.RowsAffected()
	if _, e = tx.ExecContext(ctx, `UPDATE findings SET rule_version=?,title=?,summary=?,severity=?,source_ip=?,last_seen=MAX(last_seen,?),event_count=event_count+?,observables_json=?,updated_at=?,status=CASE WHEN status='resolved' AND ?>0 THEN 'open' ELSE status END WHERE id=?`, input.RuleVersion, input.Title, input.Summary, input.Severity, input.SourceIP, seen, added, string(observables), now, added, id); e != nil {
		return Finding{}, false, e
	}
	if e = tx.Commit(); e != nil {
		return Finding{}, false, e
	}
	finding, e := s.Finding(ctx, id)
	return finding, created || added > 0, e
}

func (s *Store) Finding(ctx context.Context, id string) (Finding, error) {
	var v Finding
	var observables string
	e := s.db.QueryRowContext(ctx, `SELECT id,rule,rule_version,fingerprint,title,summary,severity,status,COALESCE(source_ip,''),first_seen,last_seen,event_count,observables_json,updated_at FROM findings WHERE id=?`, id).Scan(&v.ID, &v.Rule, &v.RuleVersion, &v.Fingerprint, &v.Title, &v.Summary, &v.Severity, &v.Status, &v.SourceIP, &v.FirstSeen, &v.LastSeen, &v.EventCount, &observables, &v.UpdatedAt)
	_ = json.Unmarshal([]byte(observables), &v.Observables)
	return v, e
}

func (s *Store) Findings(ctx context.Context, limit, offset int, status, source string) ([]Finding, int64, error) {
	where, args := "1=1", []any{}
	if status != "" {
		where, args = "status=?", append(args, status)
	}
	if source != "" {
		where += " AND source_ip=?"
		args = append(args, source)
	}
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE `+where, args...).Scan(&total); e != nil {
		return nil, 0, e
	}
	pageArgs := append(append([]any(nil), args...), limit, offset)
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM findings WHERE `+where+` ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,last_seen DESC LIMIT ? OFFSET ?`, pageArgs...)
	if e != nil {
		return nil, 0, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, 0, e
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	var out []Finding
	for _, id := range ids {
		value, readErr := s.Finding(ctx, id)
		if readErr != nil {
			return nil, 0, readErr
		}
		out = append(out, value)
	}
	return out, total, nil
}

func (s *Store) FindingEvents(ctx context.Context, id string, limit, offset int) ([]EventRecord, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_events WHERE finding_id=?`, id).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT finding_events.event_id FROM finding_events JOIN events ON events.id=finding_events.event_id WHERE finding_events.finding_id=? ORDER BY events.timestamp DESC LIMIT ? OFFSET ?`, id, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	var ids []string
	for rows.Next() {
		var eventID string
		if e = rows.Scan(&eventID); e != nil {
			rows.Close()
			return nil, 0, e
		}
		ids = append(ids, eventID)
	}
	if e = rows.Close(); e != nil {
		return nil, 0, e
	}
	out := make([]EventRecord, 0, len(ids))
	for _, eventID := range ids {
		event, readErr := s.Event(ctx, eventID)
		if readErr != nil {
			return nil, 0, readErr
		}
		out = append(out, event)
	}
	return out, total, nil
}

func (s *Store) UpdateFindingStatus(ctx context.Context, id, status string) error {
	if status != "open" && status != "acknowledged" && status != "resolved" {
		return fmt.Errorf("invalid finding status")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, e := s.db.ExecContext(ctx, `UPDATE findings SET status=?,updated_at=? WHERE id=?`, status, time.Now().UTC().Format(time.RFC3339Nano), id)
	if e != nil {
		return e
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("finding not found")
	}
	return nil
}

func (s *Store) ReserveFindingAlert(ctx context.Context, id string, cooldown time.Duration) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	now := time.Now().UTC()
	cutoff := now.Add(-cooldown).Format(time.RFC3339Nano)
	result, e := s.db.ExecContext(ctx, `UPDATE findings SET last_alerted_at=?,updated_at=? WHERE id=? AND (last_alerted_at IS NULL OR last_alerted_at<=?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id, cutoff)
	if e != nil {
		return false, e
	}
	affected, _ := result.RowsAffected()
	return affected == 1, nil
}

type AlertDelivery struct {
	ID          string  `json:"id"`
	AlertID     string  `json:"alert_id"`
	Endpoint    string  `json:"endpoint"`
	Payload     []byte  `json:"-"`
	Status      string  `json:"status"`
	Attempts    int     `json:"attempts"`
	NextAttempt string  `json:"next_attempt"`
	LastError   string  `json:"last_error,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	DeliveredAt *string `json:"delivered_at,omitempty"`
}

type ArtifactAnalysis struct {
	ArtifactID string         `json:"artifact_id"`
	Status     string         `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	Error      string         `json:"error,omitempty"`
	CreatedAt  string         `json:"created_at"`
	UpdatedAt  string         `json:"updated_at"`
}

func (s *Store) QueueArtifactAnalysis(ctx context.Context, artifactID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, e := s.db.ExecContext(ctx, `INSERT INTO artifact_analysis(artifact_id,status,result_json,error,created_at,updated_at) VALUES(?,'pending','{}','',?,?) ON CONFLICT(artifact_id) DO UPDATE SET status='pending',error='',updated_at=excluded.updated_at`, artifactID, now, now)
	return e
}

func (s *Store) PendingArtifactAnalysis(ctx context.Context, limit int) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT artifact_id FROM artifact_analysis WHERE status='pending' ORDER BY created_at LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) CompleteArtifactAnalysis(ctx context.Context, artifactID string, result map[string]any, analysisErr error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	status, message := "complete", ""
	if analysisErr != nil {
		status, message = "failed", analysisErr.Error()
		if len(message) > 2048 {
			message = message[:2048]
		}
	}
	encoded, _ := json.Marshal(result)
	_, e := s.db.ExecContext(ctx, `UPDATE artifact_analysis SET status=?,result_json=?,error=?,updated_at=? WHERE artifact_id=?`, status, string(encoded), message, time.Now().UTC().Format(time.RFC3339Nano), artifactID)
	return e
}

func (s *Store) ArtifactAnalysis(ctx context.Context, artifactID string) (ArtifactAnalysis, error) {
	var value ArtifactAnalysis
	var result string
	e := s.db.QueryRowContext(ctx, `SELECT artifact_id,status,result_json,error,created_at,updated_at FROM artifact_analysis WHERE artifact_id=?`, artifactID).Scan(&value.ArtifactID, &value.Status, &result, &value.Error, &value.CreatedAt, &value.UpdatedAt)
	_ = json.Unmarshal([]byte(result), &value.Result)
	return value, e
}

func (s *Store) EnqueueAlertDeliveries(ctx context.Context, alertID string, payload []byte, endpoints []string) error {
	if len(endpoints) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, endpoint := range endpoints {
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO alert_deliveries(id,alert_id,endpoint,payload,status,attempts,next_attempt,last_error,created_at,updated_at) VALUES(?,?,?,?,'pending',0,?,'',?,?)`, model.NewUUIDv7(time.Now()), alertID, endpoint, payload, now, now, now); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func (s *Store) DueAlertDeliveries(ctx context.Context, now time.Time, limit int) ([]AlertDelivery, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,alert_id,endpoint,payload,status,attempts,next_attempt,last_error,created_at,updated_at,delivered_at FROM alert_deliveries WHERE status IN ('pending','retrying') AND next_attempt<=? ORDER BY next_attempt,id LIMIT ?`, now.UTC().Format(time.RFC3339Nano), limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []AlertDelivery
	for rows.Next() {
		var v AlertDelivery
		if e = rows.Scan(&v.ID, &v.AlertID, &v.Endpoint, &v.Payload, &v.Status, &v.Attempts, &v.NextAttempt, &v.LastError, &v.CreatedAt, &v.UpdatedAt, &v.DeliveredAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) CompleteAlertDelivery(ctx context.Context, id string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, e := s.db.ExecContext(ctx, `UPDATE alert_deliveries SET status='delivered',attempts=attempts+1,last_error='',updated_at=?,delivered_at=? WHERE id=?`, now, now, id)
	return e
}

func (s *Store) RetryAlertDelivery(ctx context.Context, id, message string, next time.Time, terminal bool) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	status := "retrying"
	if terminal {
		status = "failed"
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	_, e := s.db.ExecContext(ctx, `UPDATE alert_deliveries SET status=?,attempts=attempts+1,last_error=?,next_attempt=?,updated_at=? WHERE id=?`, status, message, next.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano), id)
	return e
}

func (s *Store) RetryAlertDeliveryNow(ctx context.Context, id string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, e := s.db.ExecContext(ctx, `UPDATE alert_deliveries SET status='pending',next_attempt=?,updated_at=? WHERE id=? AND status='failed'`, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano), id)
	if e != nil {
		return e
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("failed delivery not found")
	}
	return nil
}

func (s *Store) AlertDeliveries(ctx context.Context, limit, offset int) ([]AlertDelivery, int64, error) {
	var total int64
	if e := s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_deliveries`).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id,alert_id,endpoint,status,attempts,next_attempt,last_error,created_at,updated_at,delivered_at FROM alert_deliveries ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, limit, offset)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []AlertDelivery
	for rows.Next() {
		var v AlertDelivery
		if e = rows.Scan(&v.ID, &v.AlertID, &v.Endpoint, &v.Status, &v.Attempts, &v.NextAttempt, &v.LastError, &v.CreatedAt, &v.UpdatedAt, &v.DeliveredAt); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}
