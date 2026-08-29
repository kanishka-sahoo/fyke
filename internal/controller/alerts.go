package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/store"
)

type AlertEngine struct {
	store  *store.Store
	broker *Broker
	cfg    config.Alerts
	queue  chan model.Event
	seen   sync.Map
	mu     sync.Mutex
	source map[string][]time.Time
	seq    atomic.Uint64
	client *http.Client
}

func NewAlertEngine(ctx context.Context, st *store.Store, b *Broker, c config.Alerts) *AlertEngine {
	a := &AlertEngine{store: st, broker: b, cfg: c, queue: make(chan model.Event, 128), source: map[string][]time.Time{}, client: &http.Client{Timeout: 10 * time.Second}}
	go a.deliver(ctx)
	return a
}
func (a *AlertEngine) Process(e model.Event) {
	rule := ""
	switch {
	case e.Type == "authentication.attempt" && e.Outcome == "success":
		rule = "successful_emulated_login"
	case e.Type == "artifact.upload":
		rule = "artifact_upload"
	case e.Type == "sensor.unhealthy":
		rule = "unhealthy_sensor"
	}
	if fp, ok := e.Attributes["fingerprint"].(string); ok && fp != "" {
		if _, loaded := a.seen.LoadOrStore(fp, true); !loaded {
			a.raise(e, "novel_fingerprint")
		}
	}
	if a.spike(e.Source.IP) {
		a.raise(e, "source_spike")
	}
	if rule != "" {
		a.raise(e, rule)
	}
}
func (a *AlertEngine) spike(ip string) bool {
	if ip == "" || a.cfg.SourceSpikePerMinute <= 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	v := a.source[ip][:0]
	for _, t := range a.source[ip] {
		if now.Sub(t) < time.Minute {
			v = append(v, t)
		}
	}
	v = append(v, now)
	a.source[ip] = v
	return len(v) == a.cfg.SourceSpikePerMinute
}
func (a *AlertEngine) raise(trigger model.Event, rule string) {
	e := model.Event{SensorID: "controller", SessionID: trigger.SessionID, Sequence: a.seq.Add(1), Source: trigger.Source, Protocol: trigger.Protocol, Type: "alert", Outcome: "triggered", Persona: trigger.Persona, Attributes: map[string]any{"rule": rule, "trigger_event_id": trigger.ID}}
	if e.Normalize(time.Now()) != nil {
		return
	}
	if err := a.store.Insert(context.Background(), e); err != nil {
		slog.Error("store alert", "error", err)
		return
	}
	a.broker.Publish(e)
	select {
	case a.queue <- e:
	default:
		slog.Warn("alert delivery queue full", "event_id", e.ID)
	}
}
func (a *AlertEngine) deliver(ctx context.Context) {
	for {
		select {
		case e := <-a.queue:
			b, _ := json.Marshal(e)
			for _, u := range a.cfg.Webhooks {
				for attempt := 0; attempt < 4; attempt++ {
					req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
					if err != nil {
						break
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Idempotency-Key", e.ID)
					resp, err := a.client.Do(req)
					if err == nil {
						resp.Body.Close()
						if resp.StatusCode >= 200 && resp.StatusCode < 300 {
							break
						}
					}
					select {
					case <-time.After(time.Duration(1<<attempt) * time.Second):
					case <-ctx.Done():
						return
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
