package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/store"
)

type AlertEngine struct {
	store    *store.Store
	broker   *Broker
	wake     chan struct{}
	cfgMu    sync.RWMutex
	cfg      config.Alerts
	secretMu sync.RWMutex
	secret   []byte
	seq      atomic.Uint64
	client   *http.Client
}

func NewAlertEngine(ctx context.Context, st *store.Store, b *Broker, c config.Alerts) *AlertEngine {
	a := &AlertEngine{store: st, broker: b, cfg: cloneAlertConfig(c), wake: make(chan struct{}, 1), client: &http.Client{Timeout: 10 * time.Second}}
	a.setSigningSecret(ctx, c.WebhookSigningSecret)
	a.cfg.WebhookSigningSecret = ""
	go a.deliver(ctx)
	go a.monitorSensors(ctx)
	a.WakeDeliveries()
	return a
}

func cloneAlertConfig(c config.Alerts) config.Alerts {
	out := c
	out.Webhooks = append([]string(nil), c.Webhooks...)
	if c.Rules != nil {
		out.Rules = make(map[string]config.AlertRule, len(c.Rules))
		for name, rule := range c.Rules {
			out.Rules[name] = rule
		}
	}
	return out
}

func (a *AlertEngine) setSigningSecret(ctx context.Context, supplied string) {
	secret := supplied
	if secret == "" {
		protected, found, protectedErr := a.store.GetProtectedSetting(ctx, "alerts.webhook_signing_secret")
		if protectedErr == nil && found {
			secret = protected
		} else {
			_, _ = a.store.GetSetting(ctx, "alerts.webhook_signing_secret", &secret)
		}
	}
	if secret == "" {
		var raw [32]byte
		if _, e := rand.Read(raw[:]); e == nil {
			secret = base64.RawURLEncoding.EncodeToString(raw[:])
		}
	}
	if secret != "" {
		_ = a.store.SetProtectedSetting(ctx, "alerts.webhook_signing_secret", secret)
	}
	a.secretMu.Lock()
	a.secret = []byte(secret)
	a.secretMu.Unlock()
}

func (a *AlertEngine) Config() config.Alerts {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	out := cloneAlertConfig(a.cfg)
	out.WebhookSigningSecret = ""
	return out
}

func (a *AlertEngine) UpdateConfig(c config.Alerts) {
	if c.WebhookSigningSecret != "" {
		a.setSigningSecret(context.Background(), c.WebhookSigningSecret)
	}
	c.WebhookSigningSecret = ""
	a.cfgMu.Lock()
	a.cfg = cloneAlertConfig(c)
	a.cfgMu.Unlock()
}

func (a *AlertEngine) Process(event model.Event) {
	if event.SensorID == "controller" || event.Type == "alert" {
		return
	}
	observables, _ := a.store.Observables(context.Background(), event.ID)
	source := event.Source.IP
	if source != "" && a.store.SourceIgnored(context.Background(), source) {
		return
	}
	record := func(rule, fingerprint, title, summary, severity string) {
		a.recordFinding(event, store.FindingInput{Rule: rule, RuleVersion: 1, Fingerprint: fingerprint, Title: title, Summary: summary, Severity: severity, SourceIP: source, EventID: event.ID, OccurredAt: event.Timestamp, Observables: observables})
	}
	switch {
	case event.Type == "authentication.attempt" && event.Outcome == "success":
		record("successful_emulated_login", source+"\x00"+event.SessionID, "Successful emulated login", "The Source reached an interactive emulated session.", "high")
	case event.Type == "artifact.upload":
		record("artifact_upload", source+"\x00"+event.SessionID, "Artifact upload captured", "The Source placed an Artifact in encrypted quarantine.", "high")
	case event.Type == "sensor.unhealthy":
		record("unhealthy_sensor", event.SensorID, "Sensor stopped reporting", "A Sensor exceeded the health reporting window.", "high")
	case event.Type == "command":
		record("post_login_activity", source+"\x00"+event.SessionID, "Post-login commands observed", "The Source entered commands after emulated access.", "medium")
		if hasValues(event.Attributes["urls"]) {
			record("staged_download", source+"\x00"+event.SessionID, "Download staging attempted", "A network command referenced one or more remote URLs.", "high")
		}
	case event.Type == "emulation.gap":
		feature := fmt.Sprint(event.Attributes["gap"])
		if feature == "" || feature == "<nil>" {
			feature = fmt.Sprint(event.Attributes["feature"])
		}
		record("emulation_gap", event.Persona+"\x00"+feature, "Recurring emulation gap", "Attacker input reached behavior the selected Persona cannot yet model convincingly.", "low")
	}
	if fingerprint, ok := event.Attributes["fingerprint"].(string); ok && fingerprint != "" {
		seen, e := a.store.ObservableSeenBefore(context.Background(), "ssh.fingerprint", fingerprint, event.ID)
		if e == nil && !seen {
			record("novel_fingerprint", fingerprint, "New SSH key fingerprint", "Fyke observed an SSH public key fingerprint not previously stored.", "medium")
		}
	}
	if source != "" {
		threshold := a.Config().SourceSpikePerMinute
		if threshold > 0 {
			count, e := a.store.Count(context.Background(), store.Query{Source: source, Since: time.Now().Add(-time.Minute)})
			if e == nil && count >= int64(threshold) {
				bucket := time.Now().UTC().Truncate(time.Minute).Format(time.RFC3339)
				record("source_spike", source+"\x00"+bucket, "Source activity spike", "The Source exceeded the configured one-minute activity threshold.", "medium")
			}
		}
		protocols, e := a.store.SourceProtocolCount(context.Background(), source, time.Now().Add(-24*time.Hour))
		if e == nil && protocols >= 2 {
			record("cross_protocol_activity", source, "Cross-protocol activity", "The Source interacted with multiple protocol Sensors within 24 hours.", "medium")
		}
		if event.Type == "http.request" {
			requests, paths, e := a.store.HTTPEnumerationStats(context.Background(), source, time.Now().Add(-10*time.Minute))
			if e == nil && requests >= 20 && paths*4 >= requests*3 {
				record("http_enumeration", source+"\x00"+time.Now().UTC().Format("2006-01-02T15"), "Probable web enumeration", "The Source requested many distinct web paths in a short window.", "medium")
			}
		}
	}
	if event.Type == "authentication.attempt" {
		if token, reused, e := a.store.SecretReuse(context.Background(), event.ID); e == nil && reused > 1 {
			record("reused_secret", token, "Submitted secret reused", "The same protected authentication secret was observed in multiple Events.", "medium")
		}
	}
}

func hasValues(value any) bool {
	switch values := value.(type) {
	case []string:
		return len(values) > 0
	case []any:
		return len(values) > 0
	}
	return false
}

func (a *AlertEngine) recordFinding(trigger model.Event, input store.FindingInput) {
	finding, changed, e := a.store.UpsertFinding(context.Background(), input)
	if e != nil {
		slog.Error("store finding", "rule", input.Rule, "error", e)
		return
	}
	if !changed {
		return
	}
	enabled, severity, cooldown := a.rule(input.Rule, input.Severity)
	if !enabled {
		return
	}
	reserved, e := a.store.ReserveFindingAlert(context.Background(), finding.ID, cooldown)
	if e != nil || !reserved {
		return
	}
	a.raise(trigger, input.Rule, finding.ID, severity)
}

func (a *AlertEngine) rule(name, fallbackSeverity string) (bool, string, time.Duration) {
	c := a.Config()
	preference, configured := c.Rules[name]
	if !configured {
		if name == "unhealthy_sensor" {
			return true, fallbackSeverity, 0
		}
		return true, fallbackSeverity, 15 * time.Minute
	}
	severity := preference.Severity
	if severity == "" {
		severity = fallbackSeverity
	}
	cooldown := time.Duration(preference.CooldownMinutes) * time.Minute
	return preference.Enabled, severity, cooldown
}

func (a *AlertEngine) raise(trigger model.Event, rule, findingID, severity string) bool {
	event := model.Event{ID: model.NewUUIDv7(time.Now()), SensorID: "controller", Sequence: a.seq.Add(1), Source: trigger.Source, Protocol: trigger.Protocol, Type: "alert", Outcome: "triggered", Persona: trigger.Persona, Attributes: map[string]any{"rule": rule, "finding_id": findingID, "trigger_event_id": trigger.ID, "severity": severity}}
	event.SessionID = event.ID
	if event.Normalize(time.Now()) != nil {
		return false
	}
	if e := a.store.Insert(context.Background(), event); e != nil {
		slog.Error("store alert", "error", e)
		return false
	}
	a.broker.Publish(event)
	payload, _ := json.Marshal(event)
	if e := a.store.EnqueueAlertDeliveries(context.Background(), event.ID, payload, a.Config().Webhooks); e != nil {
		slog.Error("enqueue alert deliveries", "error", e)
		return false
	}
	a.WakeDeliveries()
	return true
}

func (a *AlertEngine) WakeDeliveries() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *AlertEngine) deliver(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.wake:
			a.deliverDue(ctx)
		case <-ticker.C:
			a.deliverDue(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *AlertEngine) deliverDue(ctx context.Context) {
	for {
		items, e := a.store.DueAlertDeliveries(ctx, time.Now(), 20)
		if e != nil {
			slog.Error("load alert deliveries", "error", e)
			return
		}
		if len(items) == 0 {
			return
		}
		for _, item := range items {
			a.deliverOne(ctx, item)
		}
	}
}

func (a *AlertEngine) deliverOne(ctx context.Context, item store.AlertDelivery) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, item.Endpoint, bytes.NewReader(item.Payload))
	if e == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", item.AlertID)
		req.Header.Set("X-Fyke-Timestamp", timestamp)
		req.Header.Set("X-Fyke-Signature", "sha256="+a.signature(timestamp, item.Payload))
		response, requestErr := a.client.Do(req)
		e = requestErr
		if e == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				if markErr := a.store.CompleteAlertDelivery(context.Background(), item.ID); markErr != nil {
					slog.Error("complete alert delivery", "error", markErr)
				}
				return
			}
			e = fmt.Errorf("webhook returned %s", response.Status)
		}
	}
	attempt := item.Attempts + 1
	terminal := attempt >= 8
	delay := time.Duration(1<<min(attempt, 10)) * time.Second
	if delay > time.Hour {
		delay = time.Hour
	}
	if markErr := a.store.RetryAlertDelivery(context.Background(), item.ID, e.Error(), time.Now().Add(delay), terminal); markErr != nil {
		slog.Error("retry alert delivery", "error", markErr)
	}
}

func (a *AlertEngine) signature(timestamp string, payload []byte) string {
	a.secretMu.RLock()
	defer a.secretMu.RUnlock()
	h := hmac.New(sha256.New, a.secret)
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *AlertEngine) monitorSensors(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			if e := a.checkSensorHealth(ctx, now); e != nil {
				slog.Error("sensor health check failed", "error", e)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *AlertEngine) checkSensorHealth(ctx context.Context, now time.Time) error {
	sensors, e := a.store.SensorHealth(ctx, now, 2*time.Minute)
	if e != nil {
		return e
	}
	for _, health := range sensors {
		if health.Status != "unhealthy" || health.RecordedStatus == "unhealthy" {
			continue
		}
		trigger := model.Event{ID: model.NewUUIDv7(now), Timestamp: now, SensorID: health.ID, SessionID: "sensor-health-" + health.ID, Sequence: health.LastSequence + 1, Protocol: "sensor", Type: "sensor.unhealthy", Outcome: "failure", Attributes: map[string]any{"sensor_id": health.ID, "last_seen": health.LastSeen}}
		if e = a.store.Insert(ctx, trigger); e != nil {
			return e
		}
		a.Process(trigger)
		if e = a.store.SetSensorStatus(ctx, health.ID, "unhealthy"); e != nil {
			return e
		}
	}
	return nil
}
