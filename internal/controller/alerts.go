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
	store     *store.Store
	broker    *Broker
	queue     chan model.Event
	seen      sync.Map
	cfgMu     sync.RWMutex
	cfg       config.Alerts
	sourceMu  sync.Mutex
	source    map[string][]time.Time
	healthMu  sync.Mutex
	unhealthy map[string]bool
	seq       atomic.Uint64
	client    *http.Client
}

func NewAlertEngine(ctx context.Context, st *store.Store, b *Broker, c config.Alerts) *AlertEngine {
	a := &AlertEngine{store: st, broker: b, cfg: c, queue: make(chan model.Event, 128), source: map[string][]time.Time{}, unhealthy: map[string]bool{}, client: &http.Client{Timeout: 10 * time.Second}}
	go a.deliver(ctx)
	go a.monitorSensors(ctx)
	return a
}
func (a *AlertEngine) Config() config.Alerts {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return config.Alerts{Webhooks: append([]string(nil), a.cfg.Webhooks...), SourceSpikePerMinute: a.cfg.SourceSpikePerMinute}
}
func (a *AlertEngine) UpdateConfig(c config.Alerts) {
	a.cfgMu.Lock()
	a.cfg = config.Alerts{Webhooks: append([]string(nil), c.Webhooks...), SourceSpikePerMinute: c.SourceSpikePerMinute}
	a.cfgMu.Unlock()
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
	threshold := a.Config().SourceSpikePerMinute
	if ip == "" || threshold <= 0 {
		return false
	}
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()
	now := time.Now()
	v := a.source[ip][:0]
	for _, t := range a.source[ip] {
		if now.Sub(t) < time.Minute {
			v = append(v, t)
		}
	}
	v = append(v, now)
	a.source[ip] = v
	return len(v) == threshold
}
func (a *AlertEngine) raise(trigger model.Event, rule string) bool {
	e := model.Event{ID: model.NewUUIDv7(time.Now()), SensorID: "controller", Sequence: a.seq.Add(1), Source: trigger.Source, Protocol: trigger.Protocol, Type: "alert", Outcome: "triggered", Persona: trigger.Persona, Attributes: map[string]any{"rule": rule, "trigger_event_id": trigger.ID}}
	e.SessionID = e.ID
	if e.Normalize(time.Now()) != nil {
		return false
	}
	if err := a.store.Insert(context.Background(), e); err != nil {
		slog.Error("store alert", "error", err)
		return false
	}
	a.broker.Publish(e)
	select {
	case a.queue <- e:
	default:
		slog.Warn("alert delivery queue full", "event_id", e.ID)
	}
	return true
}
func (a *AlertEngine) deliver(ctx context.Context) {
	for {
		select {
		case e := <-a.queue:
			b, _ := json.Marshal(e)
			for _, u := range a.Config().Webhooks {
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
		a.healthMu.Lock()
		wasUnhealthy := a.unhealthy[health.ID] || health.RecordedStatus == "unhealthy"
		if health.Status != "unhealthy" {
			delete(a.unhealthy, health.ID)
		} else if wasUnhealthy {
			a.unhealthy[health.ID] = true
		}
		a.healthMu.Unlock()
		if health.Status != "unhealthy" || wasUnhealthy {
			continue
		}
		trigger := model.Event{ID: model.NewUUIDv7(now), SensorID: health.ID, SessionID: "sensor-health-" + health.ID, Sequence: health.LastSequence, Protocol: "sensor", Type: "sensor.unhealthy", Outcome: "failure", Attributes: map[string]any{"sensor_id": health.ID, "last_seen": health.LastSeen}}
		if a.raise(trigger, "unhealthy_sensor") {
			if e = a.store.SetSensorStatus(ctx, health.ID, "unhealthy"); e != nil {
				return e
			}
			a.healthMu.Lock()
			a.unhealthy[health.ID] = true
			a.healthMu.Unlock()
		}
	}
	return nil
}
