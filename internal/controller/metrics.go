package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ksahoo/fyke/internal/store"
)

func ServeMetrics(ctx context.Context, address string, st *store.Store) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		o, e := st.Overview(r.Context())
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE fyke_events_24h gauge\nfyke_events_24h %d\n# TYPE fyke_sessions_24h gauge\nfyke_sessions_24h %d\n# TYPE fyke_sources_24h gauge\nfyke_sources_24h %d\n# TYPE fyke_artifacts_24h gauge\nfyke_artifacts_24h %d\n", o.Events24h, o.Sessions24h, o.Sources24h, o.Artifacts24h)
	})
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if e := st.IntegrityCheck(r.Context()); e != nil {
			http.Error(w, "not ready", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(c)
	}()
	e := s.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
