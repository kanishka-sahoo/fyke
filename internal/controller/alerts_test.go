package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestEmptyAlertPreferencesUseJSONArray(t *testing.T) {
	encoded, e := json.Marshal(cloneAlertConfig(config.Alerts{}))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(encoded), `"webhooks":[]`) {
		t.Fatalf("preferences = %s, want empty webhook array", encoded)
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

func TestEventsReturnsFilteredPaginationTotal(t *testing.T) {
	st := alertTestStore(t)
	ctx := context.Background()
	for sequence, eventType := range []string{"command", "session.start", "command"} {
		event := model.Event{SensorID: "ssh", SessionID: "session", Sequence: uint64(sequence + 1), Source: model.Endpoint{IP: "192.0.2.8"}, Protocol: "ssh", Type: eventType, Outcome: "success"}
		if e := st.Insert(ctx, event); e != nil {
			t.Fatal(e)
		}
	}
	api := NewAPI(st, NewBroker(), nil, config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?type=command&limit=1&offset=1", nil)
	response := httptest.NewRecorder()
	api.events(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Items  []model.Event `json:"items"`
		Total  int64         `json:"total"`
		Limit  int           `json:"limit"`
		Offset int           `json:"offset"`
	}
	if e := json.NewDecoder(response.Body).Decode(&body); e != nil {
		t.Fatal(e)
	}
	if len(body.Items) != 1 || body.Total != 2 || body.Limit != 1 || body.Offset != 1 {
		t.Fatalf("pagination response = %#v", body)
	}
}

func TestEventsEmptyCollectionUsesJSONArray(t *testing.T) {
	api := NewAPI(alertTestStore(t), NewBroker(), nil, config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	response := httptest.NewRecorder()
	api.events(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Items json.RawMessage `json:"items"`
	}
	if e := json.NewDecoder(response.Body).Decode(&body); e != nil {
		t.Fatal(e)
	}
	if string(body.Items) != "[]" {
		t.Fatalf("items = %s, want []", body.Items)
	}
}

func TestEventsRejectsInvalidTimeRange(t *testing.T) {
	api := NewAPI(alertTestStore(t), NewBroker(), nil, config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?since=not-a-time", nil)
	response := httptest.NewRecorder()
	api.events(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestWebhookDeliveryIsDurableIdempotentAndSigned(t *testing.T) {
	st := alertTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secret := "0123456789abcdef0123456789abcdef"
	var received bool
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skipf("local sockets unavailable: %v", e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		timestamp := r.Header.Get("X-Fyke-Timestamp")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(timestamp + "."))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-Fyke-Signature") != want {
			t.Errorf("signature=%q want=%q", r.Header.Get("X-Fyke-Signature"), want)
		}
		if r.Header.Get("Idempotency-Key") != "alert-1" {
			t.Errorf("idempotency key=%q", r.Header.Get("Idempotency-Key"))
		}
		received = true
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	engine := NewAlertEngine(ctx, st, NewBroker(), config.Alerts{WebhookSigningSecret: secret})
	var storedSecret string
	if e = st.DB().QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key='alerts.webhook_signing_secret'`).Scan(&storedSecret); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(storedSecret, secret) {
		t.Fatal("webhook signing secret stored in plaintext")
	}
	engine.client = server.Client()
	payload := []byte(`{"id":"alert-1"}`)
	if e := st.EnqueueAlertDeliveries(ctx, "alert-1", payload, []string{server.URL}); e != nil {
		t.Fatal(e)
	}
	items, e := st.DueAlertDeliveries(ctx, time.Now().Add(time.Second), 1)
	if e != nil || len(items) != 1 {
		t.Fatalf("deliveries=%#v error=%v", items, e)
	}
	engine.deliverOne(ctx, items[0])
	if !received {
		t.Fatal("webhook not received")
	}
	items, _, e = st.AlertDeliveries(ctx, 10, 0)
	if e != nil || len(items) != 1 || items[0].Status != "delivered" || items[0].Attempts != 1 {
		t.Fatalf("stored delivery=%#v error=%v", items, e)
	}
}

func TestWebhookSigningSecretIsProtectedAtRest(t *testing.T) {
	st := alertTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secret := "0123456789abcdef0123456789abcdef"
	_ = NewAlertEngine(ctx, st, NewBroker(), config.Alerts{WebhookSigningSecret: secret})
	var raw string
	if e := st.DB().QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key='alerts.webhook_signing_secret'`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(raw, secret) {
		t.Fatal("webhook signing secret stored in plaintext")
	}
}
