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
	"net/netip"
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
	artifactAnalyzer      *ArtifactAnalyzer
	cfg                   config.Config
	started               time.Time
	isTrustedLocalRequest func(string) bool
}

func (a *API) SetArtifactAnalyzer(analyzer *ArtifactAnalyzer) { a.artifactAnalyzer = analyzer }

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
	mux.HandleFunc("GET /api/v1/events/{id}", a.event)
	mux.HandleFunc("GET /api/v1/stream", a.stream)
	mux.HandleFunc("GET /api/v1/sessions", a.sessions)
	mux.HandleFunc("GET /api/v1/sources", a.sources)
	mux.HandleFunc("GET /api/v1/sources/{ip}/context", a.sourceContext)
	mux.HandleFunc("PUT /api/v1/sources/{ip}/context", a.sourceContext)
	mux.HandleFunc("POST /api/v1/source-context/import", a.importSourceContext)
	mux.HandleFunc("GET /api/v1/artifacts", a.artifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/preview", a.preview)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/download", a.download)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/analysis", a.artifactAnalysis)
	mux.HandleFunc("POST /api/v1/artifacts/{id}/analysis", a.queueArtifactAnalysis)
	mux.HandleFunc("POST /api/v1/investigation-bundles", a.investigationBundle)
	mux.HandleFunc("GET /api/v1/alerts", a.alerts)
	mux.HandleFunc("GET /api/v1/findings", a.findings)
	mux.HandleFunc("GET /api/v1/findings/{id}", a.finding)
	mux.HandleFunc("GET /api/v1/findings/{id}/events", a.findingEvents)
	mux.HandleFunc("PUT /api/v1/findings/{id}/status", a.findingStatus)
	mux.HandleFunc("GET /api/v1/observables", a.observablePivot)
	mux.HandleFunc("GET /api/v1/alert-deliveries", a.alertDeliveries)
	mux.HandleFunc("POST /api/v1/alert-deliveries/{id}/retry", a.retryAlertDelivery)
	mux.HandleFunc("GET /api/v1/exports", a.export)
	mux.HandleFunc("GET /api/v1/audit", a.audit)
	mux.HandleFunc("GET /api/v1/storage", a.storage)
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
	q, e := parseEventQuery(r)
	if e != nil {
		problem(w, http.StatusBadRequest, e.Error())
		return
	}
	v, e := a.store.List(r.Context(), q)
	if e != nil {
		respond(w, nil, e)
		return
	}
	total, e := a.store.Count(r.Context(), q)
	respondPage(w, v, q.Limit, q.Offset, total, e)
}

func parseEventQuery(r *http.Request) (store.Query, error) {
	qv := r.URL.Query()
	limit, offset := pageValues(r)
	q := store.Query{Limit: limit, Offset: offset, Protocol: qv.Get("protocol"), Type: qv.Get("type"), Outcome: qv.Get("outcome"), Source: qv.Get("source"), Session: qv.Get("session"), Search: qv.Get("q")}
	var e error
	if raw := qv.Get("since"); raw != "" {
		if q.Since, e = time.Parse(time.RFC3339, raw); e != nil {
			return q, fmt.Errorf("since must be an RFC3339 timestamp")
		}
	}
	if raw := qv.Get("until"); raw != "" {
		if q.Until, e = time.Parse(time.RFC3339, raw); e != nil {
			return q, fmt.Errorf("until must be an RFC3339 timestamp")
		}
	}
	if !q.Since.IsZero() && !q.Until.IsZero() && q.Until.Before(q.Since) {
		return q, fmt.Errorf("until must not be earlier than since")
	}
	return q, nil
}

func pageValues(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
func (a *API) event(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Event(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, http.StatusNotFound, "event not found")
		return
	}
	respond(w, v, nil)
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
	limit, offset := pageValues(r)
	items, total, e := a.store.Sessions(r.Context(), limit, offset)
	respondPage(w, items, limit, offset, total, e)
}
func (a *API) sources(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.Sources(r.Context(), limit, offset)
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) sourceContext(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if _, e := netip.ParseAddr(ip); e != nil {
		problem(w, http.StatusBadRequest, "invalid source address")
		return
	}
	if r.Method == http.MethodGet {
		value, e := a.store.SourceContext(r.Context(), ip)
		if e != nil {
			respond(w, store.SourceContext{SourceIP: ip}, nil)
			return
		}
		respond(w, value, nil)
		return
	}
	var value store.SourceContext
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&value); e != nil {
		problem(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	value.SourceIP = ip
	if e := a.store.SetSourceContext(r.Context(), value); e != nil {
		problem(w, http.StatusBadRequest, e.Error())
		return
	}
	_ = a.store.Audit(r.Context(), "source.context.update", r.RemoteAddr, value)
	respond(w, value, nil)
}

func (a *API) importSourceContext(w http.ResponseWriter, r *http.Request) {
	var items []store.SourceContext
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&items); e != nil || len(items) == 0 || len(items) > 10000 {
		problem(w, http.StatusBadRequest, "body must contain 1 to 10000 source context records")
		return
	}
	for _, value := range items {
		if _, e := netip.ParseAddr(value.SourceIP); e != nil {
			problem(w, http.StatusBadRequest, "invalid source address")
			return
		}
		if len(value.Label) > 256 || len(value.Country) > 128 || len(value.ASN) > 128 {
			problem(w, http.StatusBadRequest, "invalid source context")
			return
		}
	}
	for _, value := range items {
		if e := a.store.SetSourceContext(r.Context(), value); e != nil {
			problem(w, http.StatusBadRequest, e.Error())
			return
		}
	}
	_ = a.store.Audit(r.Context(), "source.context.import", r.RemoteAddr, map[string]any{"records": len(items)})
	respond(w, map[string]any{"imported": len(items)}, nil)
}
func (a *API) artifacts(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.Artifacts(r.Context(), limit, offset, r.URL.Query().Get("sha256"))
	respondPage(w, items, limit, offset, total, e)
}
func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	query := store.Query{Limit: limit, Offset: offset, Type: "alert"}
	rows, e := a.store.List(r.Context(), query)
	if e != nil {
		respond(w, nil, e)
		return
	}
	total, e := a.store.Count(r.Context(), query)
	respondPage(w, rows, limit, offset, total, e)
}

func (a *API) findings(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.Findings(r.Context(), limit, offset, r.URL.Query().Get("status"), r.URL.Query().Get("source"))
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) finding(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Finding(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, http.StatusNotFound, "finding not found")
		return
	}
	respond(w, v, nil)
}

func (a *API) findingEvents(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.FindingEvents(r.Context(), r.PathValue("id"), limit, offset)
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) findingStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&body); e != nil {
		problem(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if e := a.store.UpdateFindingStatus(r.Context(), r.PathValue("id"), body.Status); e != nil {
		problem(w, http.StatusBadRequest, e.Error())
		return
	}
	_ = a.store.Audit(r.Context(), "finding.status.update", r.RemoteAddr, map[string]any{"finding_id": r.PathValue("id"), "status": body.Status})
	respond(w, map[string]any{"status": body.Status}, nil)
}

func (a *API) observablePivot(w http.ResponseWriter, r *http.Request) {
	kind, value := r.URL.Query().Get("kind"), r.URL.Query().Get("value")
	if kind == "" || value == "" {
		problem(w, http.StatusBadRequest, "kind and value are required")
		return
	}
	limit, offset := pageValues(r)
	items, total, e := a.store.PivotEvents(r.Context(), kind, value, limit, offset)
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) alertDeliveries(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.AlertDeliveries(r.Context(), limit, offset)
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) retryAlertDelivery(w http.ResponseWriter, r *http.Request) {
	if e := a.store.RetryAlertDeliveryNow(r.Context(), r.PathValue("id")); e != nil {
		problem(w, http.StatusBadRequest, e.Error())
		return
	}
	a.alertEngine.WakeDeliveries()
	_ = a.store.Audit(r.Context(), "alert.delivery.retry", r.RemoteAddr, map[string]any{"delivery_id": r.PathValue("id")})
	respond(w, map[string]any{"status": "pending"}, nil)
}
func (a *API) preview(w http.ResponseWriter, r *http.Request) {
	meta, b, e := a.store.Evidence(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, 404, "artifact not found")
		return
	}
	_ = a.store.Audit(r.Context(), "artifact.preview", r.RemoteAddr, map[string]any{"artifact_id": meta.ID})
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

func (a *API) artifactAnalysis(w http.ResponseWriter, r *http.Request) {
	value, e := a.store.ArtifactAnalysis(r.Context(), r.PathValue("id"))
	if e != nil {
		problem(w, http.StatusNotFound, "artifact analysis not found")
		return
	}
	respond(w, value, nil)
}

func (a *API) queueArtifactAnalysis(w http.ResponseWriter, r *http.Request) {
	if a.artifactAnalyzer == nil {
		problem(w, http.StatusServiceUnavailable, "artifact worker is not enabled")
		return
	}
	if _, e := a.store.Artifact(r.Context(), r.PathValue("id")); e != nil {
		problem(w, http.StatusNotFound, "artifact not found")
		return
	}
	if e := a.store.QueueArtifactAnalysis(r.Context(), r.PathValue("id")); e != nil {
		respond(w, nil, e)
		return
	}
	a.artifactAnalyzer.Wake()
	_ = a.store.Audit(r.Context(), "artifact.analysis.queue", r.RemoteAddr, map[string]any{"artifact_id": r.PathValue("id")})
	respond(w, map[string]any{"status": "pending"}, nil)
}
func (a *API) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	if r.URL.Query().Get("sensitive") == "true" {
		problem(w, http.StatusBadRequest, "sensitive evidence requires an encrypted investigation bundle")
		return
	}
	if format != "csv" && format != "jsonl" {
		problem(w, 400, "format must be jsonl or csv")
		return
	}
	q, e := parseEventQuery(r)
	if e != nil {
		problem(w, http.StatusBadRequest, e.Error())
		return
	}
	a.store.Audit(r.Context(), "events.export", r.RemoteAddr, map[string]any{"format": format, "filters": r.URL.Query()})
	w.Header().Set("Content-Disposition", "attachment; filename=fyke-events."+format)
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		cw := csv.NewWriter(w)
		if e = cw.Write([]string{"id", "timestamp", "sensor_id", "session_id", "source_ip", "protocol", "event_type", "outcome"}); e != nil {
			return
		}
		_, e = a.store.ForEachSnapshot(r.Context(), q, func(x store.EventRecord) error {
			return cw.Write([]string{x.ID, x.Timestamp.Format(time.RFC3339Nano), x.SensorID, x.SessionID, x.Source.IP, x.Protocol, x.Type, x.Outcome})
		})
		cw.Flush()
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		_, e = a.store.ForEachSnapshot(r.Context(), q, func(x store.EventRecord) error { return enc.Encode(x) })
	}
	if e != nil {
		slog.Error("stream export", "error", e)
	}
}

func (a *API) audit(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageValues(r)
	items, total, e := a.store.AuditRecords(r.Context(), limit, offset)
	respondPage(w, items, limit, offset, total, e)
}

func (a *API) storage(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.StorageStatus(r.Context())
	if e != nil {
		respond(w, nil, e)
		return
	}
	var last any
	_, _ = a.store.GetSetting(r.Context(), "retention.last_result", &last)
	respond(w, map[string]any{"usage": v, "limit_bytes": a.cfg.Retention.TotalBytes, "last_retention": last}, nil)
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	e := a.store.IntegrityCheck(r.Context())
	if e != nil {
		respond(w, nil, e)
		return
	}
	status := "healthy"
	details := map[string]any{"uptime_seconds": int(time.Since(a.started).Seconds())}
	if storage, storageErr := a.store.StorageStatus(r.Context()); storageErr == nil {
		details["storage_bytes"] = storage.TotalBytes
		details["storage_limit_bytes"] = a.cfg.Retention.TotalBytes
		if a.cfg.Retention.TotalBytes > 0 && storage.TotalBytes >= a.cfg.Retention.TotalBytes {
			status = "capacity_exhausted"
		} else if a.cfg.Retention.TotalBytes > 0 && storage.TotalBytes*100 >= a.cfg.Retention.TotalBytes*90 {
			status = "degraded"
		}
	}
	details["status"] = status
	respond(w, details, nil)
}
func (a *API) retention(w http.ResponseWriter, r *http.Request) {
	var last map[string]any
	found, e := a.store.GetSetting(r.Context(), "retention.last_result", &last)
	if e != nil {
		respond(w, nil, e)
		return
	}
	value := map[string]any{"policy": a.cfg.Retention}
	if found {
		value["last_result"] = last
	}
	respond(w, value, nil)
}
func (a *API) runRetention(w http.ResponseWriter, r *http.Request) {
	p := a.cfg.Retention
	v, e := a.store.Prune(r.Context(), store.RetentionPolicy{MetadataDays: p.MetadataDays, TranscriptDays: p.TranscriptDays, PCAPDays: p.PCAPDays, PayloadDays: p.PayloadDays, TotalBytes: p.TotalBytes})
	if e == nil {
		_ = a.store.SetSetting(r.Context(), "retention.last_result", map[string]any{"ran_at": time.Now().UTC(), "result": v})
	}
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
	stored := v
	stored.WebhookSigningSecret = ""
	e := a.store.SetSetting(r.Context(), "alerts", stored)
	if e == nil {
		a.alertEngine.UpdateConfig(v)
		a.store.Audit(r.Context(), "alerts.preferences.update", r.RemoteAddr, stored)
	}
	respond(w, stored, e)
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

func respondPage[T any](w http.ResponseWriter, items []T, limit, offset int, total int64, e error) {
	if items == nil {
		items = []T{}
	}
	respond(w, map[string]any{"items": items, "limit": limit, "offset": offset, "total": total}, e)
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
