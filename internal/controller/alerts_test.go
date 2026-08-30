package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/store"
)

func alertTestStore(t *testing.T) *store.Store {
	t.Helper()
	root := t.TempDir()
	id := filepath.Join(root, "identity")
	if _, e := cryptokit.GenerateIdentity(id); e != nil {
		t.Fatal(e)
	}
	sealer, e := cryptokit.Load(id)
	if e != nil {
		t.Fatal(e)
	}
	st, e := store.Open(filepath.Join(root, "data"), sealer)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestAlertPreferencesApplyAndPersist(t *testing.T) {
	st := alertTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := NewBroker()
	engine := NewAlertEngine(ctx, st, broker, config.Alerts{SourceSpikePerMinute: 60})
	api := NewAPI(st, broker, engine, config.Config{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/preferences/alerts", bytes.NewBufferString(`{"webhooks":["https://example.com/hook"],"source_spike_per_minute":7}`))
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	api.alertPreferences(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := engine.Config(); got.SourceSpikePerMinute != 7 || len(got.Webhooks) != 1 {
		t.Fatalf("runtime config = %#v", got)
	}
	var persisted config.Alerts
	found, e := st.GetSetting(ctx, "alerts", &persisted)
	if e != nil || !found || persisted.SourceSpikePerMinute != 7 {
		t.Fatalf("persisted config = %#v, %t, %v", persisted, found, e)
	}
}

func TestUnhealthySensorRaisesOneAlertPerTransition(t *testing.T) {
	st := alertTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := NewAlertEngine(ctx, st, NewBroker(), config.Alerts{})
	now := time.Now().UTC()
	old := model.Event{Timestamp: now.Add(-3 * time.Minute), SensorID: "ssh", SessionID: "session", Sequence: 1, Protocol: "ssh", Type: "session.start"}
	if e := st.Insert(ctx, old); e != nil {
		t.Fatal(e)
	}
	if e := engine.checkSensorHealth(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e := engine.checkSensorHealth(ctx, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var alerts int
	if e := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM events WHERE event_type='alert'`).Scan(&alerts); e != nil || alerts != 1 {
		t.Fatalf("alerts = %d, %v", alerts, e)
	}
	if e := st.TouchSensor(ctx, "ssh", now); e != nil {
		t.Fatal(e)
	}
	if e := engine.checkSensorHealth(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e := engine.checkSensorHealth(ctx, now.Add(3*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM events WHERE event_type='alert'`).Scan(&alerts); e != nil || alerts != 2 {
		t.Fatalf("alerts after second transition = %d, %v", alerts, e)
	}
}
