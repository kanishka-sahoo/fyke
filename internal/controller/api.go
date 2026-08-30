package controller

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/store"
)

type API struct {
	store                 *store.Store
	broker                *Broker
	alertEngine           *AlertEngine
	cfg                   config.Config
	started               time.Time
	isTrustedLocalRequest func(string) bool
}

func NewAPI(st *store.Store, b *Broker, alerts *AlertEngine, c config.Config) *API {
	return &API{
		store:                 st,
		broker:                b,
		alertEngine:           alerts,
		cfg:                   c,
		started:               time.Now(),
		isTrustedLocalRequest: trustedLocalRequest,
	}
}
func (a *API) Handler(ui http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/overview", a.overview)
	mux.HandleFunc("GET /api/v1/events", a.events)
	mux.HandleFunc("GET /api/v1/stream", a.stream)
	mux.HandleFunc("GET /api/v1/sessions", a.sessions)
	mux.HandleFunc("GET /api/v1/sources", a.sources)
	mux.HandleFunc("GET /api/v1/artifacts", a.artifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/preview", a.preview)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/download", a.download)
	mux.HandleFunc("GET /api/v1/alerts", a.alerts)
	mux.HandleFunc("GET /api/v1/exports", a.export)
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/retention", a.retention)
	mux.HandleFunc("POST /api/v1/retention/run", a.runRetention)
	mux.HandleFunc("GET /api/v1/preferences/alerts", a.alertPreferences)
	mux.HandleFunc("PUT /api/v1/preferences/alerts", a.alertPreferences)
	mux.Handle("/", ui)
	return a.security(a.auth(mux))
}
func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.trustedLocalRequest(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		want := a.cfg.Access.BearerToken
		if want != "" && len(token) == len(want) && subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		problem(w, http.StatusUnauthorized, "access denied")
	})
}

func (a *API) trustedLocalRequest(remoteAddr string) bool {
	if a.isTrustedLocalRequest != nil {
		return a.isTrustedLocalRequest(remoteAddr)
	}
	return trustedLocalRequest(remoteAddr)
}

func trustedLocalRequest(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if os.Getenv("FYKE_CONTAINER") != "1" || !ip.IsPrivate() {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	return err == nil && isDirectGateway(ip, addrs)
}

// isDirectGateway recognizes Docker's source address for a host-published
// loopback port: the first usable private address on a directly attached
// container subnet. Peer containers retain their own source addresses.
func isDirectGateway(remote net.IP, addrs []net.Addr) bool {
	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		local := network.IP
		candidate := remote
		if v4 := local.To4(); v4 != nil {
			local = v4
			candidate = remote.To4()
			if candidate == nil {
				continue
			}
		} else if remote.To4() != nil {
			continue
		}
		gateway := append(net.IP(nil), local.Mask(network.Mask)...)
		for i := len(gateway) - 1; i >= 0; i-- {
			gateway[i]++
			if gateway[i] != 0 {
				break
			}
		}
		if candidate.Equal(gateway) {
			return true
		}
	}
	return false
}
func (a *API) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "") && !a.trustedProxy(r.RemoteAddr) {
			problem(w, http.StatusBadRequest, "untrusted proxy identity headers")
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func (a *API) trustedProxy(remote string) bool {
	host, _, _ := net.SplitHostPort(remote)
	for _, x := range a.cfg.Access.TrustedProxies {
		if host == x {
			return true
		}
	}
	return a.trustedLocalRequest(remote)
}
func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Overview(r.Context())
	respond(w, v, e)
}
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	limit, _ := strconv.Atoi(qv.Get("limit"))
	offset, _ := strconv.Atoi(qv.Get("offset"))
	q := store.Query{Limit: limit, Offset: offset, Protocol: qv.Get("protocol"), Type: qv.Get("type"), Outcome: qv.Get("outcome"), Source: qv.Get("source"), Session: qv.Get("session"), Search: qv.Get("q")}
	q.Since, _ = time.Parse(time.RFC3339, qv.Get("since"))
	q.Until, _ = time.Parse(time.RFC3339, qv.Get("until"))
	v, e := a.store.List(r.Context(), q)
	respond(w, map[string]any{"items": v, "limit": limit, "offset": offset}, e)
}
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		problem(w, 500, "stream unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	id, ch := a.broker.Subscribe()
	defer a.broker.Unsubscribe(id)
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	f.Flush()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: event\ndata: %s\n\n", b)
			f.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": keepalive\n\n")
			f.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	a.aggregate(w, r, `SELECT session_id,min(timestamp),max(timestamp),source_ip,protocol,count(*) FROM events GROUP BY session_id ORDER BY max(timestamp) DESC LIMIT ?`, []string{"session_id", "started_at", "last_seen", "source_ip", "protocol", "events"})
}
func (a *API) sources(w http.ResponseWriter, r *http.Request) {
	a.aggregate(w, r, `SELECT source_ip,min(timestamp),max(timestamp),count(*),count(DISTINCT session_id) FROM events GROUP BY source_ip ORDER BY max(timestamp) DESC LIMIT ?`, []string{"source_ip", "first_seen", "last_seen", "events", "sessions"})
}
func (a *API) artifacts(w http.ResponseWriter, r *http.Request) {
	a.aggregate(w, r, `SELECT evidence.id,evidence.event_id,evidence.kind,evidence.content_type,evidence.filename,evidence.sha256,evidence.size,evidence.created_at FROM evidence ORDER BY created_at DESC LIMIT ?`, []string{"id", "event_id", "kind", "content_type", "filename", "sha256", "size", "created_at"})
}
func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	rows, e := a.store.List(r.Context(), store.Query{Limit: 100, Type: "alert"})
	respond(w, map[string]any{"items": rows}, e)
}
func (a *API) aggregate(w http.ResponseWriter, r *http.Request, q string, cols []string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	rows, e := a.store.DB().QueryContext(r.Context(), q, limit)
	if e != nil {
		respond(w, nil, e)
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		raw := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range raw {
			ptr[i] = &raw[i]
		}
		if e = rows.Scan(ptr...); e != nil {
			respond(w, nil, e)
			return
		}
		m := map[string]any{}
		for i, k := range cols {
			if b, ok := raw[i].([]byte); ok {
				m[k] = string(b)
			} else {
				m[k] = raw[i]
			}
		}
		out = append(out, m)
	}
	respond(w, map[string]any{"items": out}, rows.Err())
}
func (a *API) preview(w http.ResponseWriter, r *http.Request) {
	meta, b, e := a.store.Evidence(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, 404, "artifact not found")
		return
	}
	const max = 64 << 10
	if len(b) > max {
		b = b[:max]
	}
	printable := true
	for _, x := range b {
		if x < 9 || (x > 13 && x < 32) {
			printable = false
			break
		}
	}
	v := map[string]any{"id": meta.ID, "filename": meta.Filename, "truncated": int64(len(b)) < meta.Size}
	if printable {
		v["encoding"] = "escaped-text"
		v["content"] = strings.ToValidUTF8(string(b), "�")
	} else {
		v["encoding"] = "hex"
		v["content"] = hex.EncodeToString(b)
	}
	respond(w, v, nil)
}
func (a *API) download(w http.ResponseWriter, r *http.Request) {
	meta, b, e := a.store.Evidence(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, 404, "artifact not found")
		return
	}
	a.store.Audit(r.Context(), "artifact.download", r.RemoteAddr, map[string]any{"artifact_id": meta.ID})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", strings.ReplaceAll(meta.Filename, "\"", "")))
	w.Write(b)
}
func (a *API) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	a.store.Audit(r.Context(), "events.export", r.RemoteAddr, map[string]any{"format": format, "sensitive": r.URL.Query().Get("sensitive") == "true"})
	rows, e := a.store.List(r.Context(), store.Query{Limit: 1000})
	if e != nil {
		respond(w, nil, e)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=fyke-events."+format)
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "timestamp", "sensor_id", "session_id", "source_ip", "protocol", "event_type", "outcome"})
		for _, x := range rows {
			cw.Write([]string{x.ID, x.Timestamp.Format(time.RFC3339Nano), x.SensorID, x.SessionID, x.Source.IP, x.Protocol, x.Type, x.Outcome})
		}
		cw.Flush()
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		for _, x := range rows {
			if r.URL.Query().Get("sensitive") == "true" {
				evidence := []map[string]any{}
				for _, ref := range x.EvidenceRefs {
					_, b, e := a.store.Evidence(r.Context(), ref.ID)
					if e == nil {
						evidence = append(evidence, map[string]any{"reference": ref, "data": b})
					}
				}
				enc.Encode(map[string]any{"event": x, "sensitive_evidence": evidence})
			} else {
				enc.Encode(x)
			}
		}
	default:
		problem(w, 400, "format must be jsonl or csv")
	}
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	e := a.store.IntegrityCheck(r.Context())
	status := "healthy"
	if e != nil {
		status = "unhealthy"
	}
	respond(w, map[string]any{"status": status, "uptime_seconds": int(time.Since(a.started).Seconds())}, e)
}
func (a *API) retention(w http.ResponseWriter, r *http.Request) { respond(w, a.cfg.Retention, nil) }
func (a *API) runRetention(w http.ResponseWriter, r *http.Request) {
	p := a.cfg.Retention
	v, e := a.store.Prune(r.Context(), store.RetentionPolicy{MetadataDays: p.MetadataDays, TranscriptDays: p.TranscriptDays, PCAPDays: p.PCAPDays, PayloadDays: p.PayloadDays, TotalBytes: p.TotalBytes})
	a.store.Audit(r.Context(), "retention.run", r.RemoteAddr, v)
	respond(w, v, e)
}
func (a *API) alertPreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		respond(w, a.alertEngine.Config(), nil)
		return
	}
	var v config.Alerts
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&v); e != nil {
		problem(w, 400, "invalid JSON")
		return
	}
	if e := decoder.Decode(&struct{}{}); e != io.EOF {
		problem(w, 400, "request body must contain one JSON object")
		return
	}
	if e := v.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	e := a.store.SetSetting(r.Context(), "alerts", v)
	if e == nil {
		a.alertEngine.UpdateConfig(v)
		a.store.Audit(r.Context(), "alerts.preferences.update", r.RemoteAddr, v)
	}
	respond(w, v, e)
}
func respond(w http.ResponseWriter, v any, e error) {
	if e != nil {
		slog.Error("api error", "error", e)
		problem(w, 500, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "title": msg})
}
func ServeHTTP(ctx context.Context, address string, h http.Handler) error {
	s := &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.Shutdown(c)
	}()
	e := s.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
