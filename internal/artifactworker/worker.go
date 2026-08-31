// Package artifactworker provides an optional, deliberately narrow service for
// inspecting hostile Artifacts outside the trusted Fyke controller.
package artifactworker

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

type Result struct {
	SHA256              string         `json:"sha256"`
	Size                int64          `json:"size"`
	DetectedContentType string         `json:"detected_content_type"`
	UTF8Text            bool           `json:"utf8_text"`
	Archive             *ArchiveResult `json:"archive,omitempty"`
}

type ArchiveResult struct {
	Format              string   `json:"format"`
	Entries             []string `json:"entries"`
	EntriesTruncated    bool     `json:"entries_truncated"`
	DeclaredBytes       uint64   `json:"declared_bytes"`
	DeclaredBytesCapped bool     `json:"declared_bytes_capped"`
}

func Analyze(body []byte) Result {
	sum := sha256.Sum256(body)
	result := Result{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)), DetectedContentType: http.DetectContentType(body), UTF8Text: utf8.Valid(body)}
	if archive := inspectZIP(body); archive != nil {
		result.Archive = archive
	} else if archive = inspectTar(body); archive != nil {
		result.Archive = archive
	}
	return result
}

func inspectZIP(body []byte) *ArchiveResult {
	reader, e := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if e != nil {
		return nil
	}
	result := &ArchiveResult{Format: "zip"}
	for index, file := range reader.File {
		if index < 200 {
			result.Entries = append(result.Entries, safeEntryName(file.Name))
		} else {
			result.EntriesTruncated = true
		}
		if file.UncompressedSize64 > (8<<30)-min(result.DeclaredBytes, 8<<30) {
			result.DeclaredBytesCapped = true
			result.DeclaredBytes = 8 << 30
		} else {
			result.DeclaredBytes += file.UncompressedSize64
		}
	}
	return result
}

func inspectTar(body []byte) *ArchiveResult {
	reader := tar.NewReader(bytes.NewReader(body))
	result := &ArchiveResult{Format: "tar"}
	for index := 0; index <= 200; index++ {
		header, e := reader.Next()
		if e == io.EOF {
			if index == 0 {
				return nil
			}
			return result
		}
		if e != nil {
			return nil
		}
		if index < 200 {
			result.Entries = append(result.Entries, safeEntryName(header.Name))
		} else {
			result.EntriesTruncated = true
		}
		if header.Size > 0 {
			value := uint64(header.Size)
			if value > (8<<30)-min(result.DeclaredBytes, 8<<30) {
				result.DeclaredBytesCapped = true
				result.DeclaredBytes = 8 << 30
			} else {
				result.DeclaredBytes += value
			}
		}
	}
	return result
}

func safeEntryName(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.TrimPrefix(path.Clean("/"+value), "/")
	if value == "" {
		return "unnamed"
	}
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func Serve(ctx context.Context, address, token string, maxBytes int64) error {
	if len(token) < 32 {
		return fmt.Errorf("artifact worker token must contain at least 32 characters")
	}
	if maxBytes < 1<<20 {
		return fmt.Errorf("artifact worker byte limit must be at least 1 MiB")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /analyze", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "access denied", http.StatusUnauthorized)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if e != nil || int64(len(body)) > maxBytes {
			http.Error(w, "artifact exceeds worker limit", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Analyze(body))
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	e := server.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
