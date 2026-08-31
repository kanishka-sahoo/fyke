package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/artifactworker"
	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/store"
)

type ArtifactAnalyzer struct {
	store  *store.Store
	config config.ArtifactWorker
	client *http.Client
	wake   chan struct{}
}

func NewArtifactAnalyzer(ctx context.Context, st *store.Store, worker config.ArtifactWorker) *ArtifactAnalyzer {
	if worker.URL == "" {
		return nil
	}
	a := &ArtifactAnalyzer{store: st, config: worker, client: &http.Client{Timeout: 60 * time.Second}, wake: make(chan struct{}, 1)}
	go a.run(ctx)
	a.Wake()
	return a
}

func (a *ArtifactAnalyzer) Wake() {
	if a == nil {
		return
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *ArtifactAnalyzer) run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.wake:
			a.process(ctx)
		case <-ticker.C:
			a.process(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *ArtifactAnalyzer) process(ctx context.Context) {
	ids, e := a.store.PendingArtifactAnalysis(ctx, 10)
	if e != nil {
		slog.Error("load artifact analysis jobs", "error", e)
		return
	}
	for _, id := range ids {
		_, body, readErr := a.store.Evidence(ctx, id)
		if readErr != nil {
			_ = a.store.CompleteArtifactAnalysis(context.Background(), id, nil, readErr)
			continue
		}
		result, analyzeErr := a.request(ctx, body)
		_ = a.store.CompleteArtifactAnalysis(context.Background(), id, result, analyzeErr)
	}
}

func (a *ArtifactAnalyzer) request(ctx context.Context, body []byte) (map[string]any, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.config.URL, "/")+"/analyze", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+a.config.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	response, e := a.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return nil, fmt.Errorf("artifact worker returned %s: %s", response.Status, string(message))
	}
	var typed artifactworker.Result
	if e = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&typed); e != nil {
		return nil, e
	}
	sum := sha256.Sum256(body)
	if typed.SHA256 != hex.EncodeToString(sum[:]) || typed.Size != int64(len(body)) {
		return nil, fmt.Errorf("artifact worker returned inconsistent identity")
	}
	encoded, _ := json.Marshal(typed)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result, nil
}
