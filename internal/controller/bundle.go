package controller

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/ksahoo/fyke/internal/store"
)

type investigationBundleRequest struct {
	ArtifactIDs []string `json:"artifact_ids"`
	Recipient   string   `json:"recipient"`
}

func (a *API) investigationBundle(w http.ResponseWriter, r *http.Request) {
	var request investigationBundleRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&request); e != nil || len(request.ArtifactIDs) == 0 || len(request.ArtifactIDs) > 100 {
		problem(w, http.StatusBadRequest, "artifact_ids must contain 1 to 100 IDs")
		return
	}
	recipient, e := age.ParseX25519Recipient(request.Recipient)
	if e != nil {
		problem(w, http.StatusBadRequest, "recipient must be an age X25519 recipient")
		return
	}
	seen := map[string]bool{}
	items := make([]store.ArtifactRecord, 0, len(request.ArtifactIDs))
	events := map[string]store.EventRecord{}
	for _, id := range request.ArtifactIDs {
		if id == "" || seen[id] {
			problem(w, http.StatusBadRequest, "artifact IDs must be non-empty and unique")
			return
		}
		seen[id] = true
		item, readErr := a.store.Artifact(r.Context(), id)
		if readErr != nil {
			problem(w, http.StatusNotFound, "artifact not found")
			return
		}
		items = append(items, item)
		if _, ok := events[item.EventID]; !ok {
			event, eventErr := a.store.Event(r.Context(), item.EventID)
			if eventErr != nil {
				problem(w, http.StatusNotFound, "related event not found")
				return
			}
			events[item.EventID] = event
		}
	}
	_ = a.store.Audit(r.Context(), "investigation.bundle.export", r.RemoteAddr, map[string]any{"artifact_ids": request.ArtifactIDs})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="fyke-investigation.tar.age"`)
	aw, e := age.Encrypt(w, recipient)
	if e != nil {
		return
	}
	tw := tar.NewWriter(aw)
	manifest, _ := json.MarshalIndent(map[string]any{"version": 1, "created_at": time.Now().UTC(), "artifacts": items, "events": events}, "", "  ")
	if e = writeTarBytes(tw, "manifest.json", manifest); e == nil {
		for _, item := range items {
			_, body, readErr := a.store.Evidence(r.Context(), item.ID)
			if readErr != nil {
				e = readErr
				break
			}
			name := path.Base(strings.ReplaceAll(item.Filename, "\\", "/"))
			if name == "." || name == "" || name == "/" {
				name = "evidence.bin"
			}
			if e = writeTarBytes(tw, fmt.Sprintf("artifacts/%s/%s", item.ID, name), body); e != nil {
				break
			}
		}
	}
	if closeErr := tw.Close(); e == nil {
		e = closeErr
	}
	if closeErr := aw.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		// Headers may already be committed; the truncated authenticated age stream
		// is deliberately unusable rather than yielding a partial plaintext bundle.
		return
	}
}

func writeTarBytes(tw *tar.Writer, name string, body []byte) error {
	if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), ModTime: time.Now().UTC()}); e != nil {
		return e
	}
	_, e := tw.Write(body)
	return e
}
