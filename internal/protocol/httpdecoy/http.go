package httpdecoy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/persona"
	"github.com/ksahoo/fyke/internal/sensor"
)

type Server struct {
	ID, Protocol, Address                   string
	Persona                                 persona.Persona
	Sink                                    sensor.Sink
	Limiter                                 *sensor.Limiter
	Idle, Cap                               time.Duration
	RequestBytes, ArtifactBytes, Transcript int64
	TLSCert, TLSKey                         string
}

func (s *Server) Serve(ctx context.Context) error {
	ln, e := net.Listen("tcp", s.Address)
	if e != nil {
		return e
	}
	if s.Protocol == "https" {
		cert, e := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey)
		if e != nil {
			return e
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go s.handle(ctx, c)
	}
}

// A bounded raw recorder sits below net/http parsing, preserving malformed input.
func (s *Server) handle(parent context.Context, c net.Conn) {
	defer c.Close()
	c = sensor.WithIdle(c, s.Idle)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	release, e := s.Limiter.Acquire(host)
	if e != nil {
		return
	}
	defer release()
	sess := sensor.NewSession(s.ID, s.Protocol, s.Persona.ID, c, s.Sink, s.Transcript)
	ctx, cancel := context.WithTimeout(parent, s.Cap)
	defer cancel()
	go func() { <-ctx.Done(); _ = c.Close() }()
	if e = sess.Emit(ctx, "session.start", "success", nil, nil); e != nil {
		return
	}
	defer sess.Emit(context.Background(), "session.end", "success", nil, nil)
	rec := &recordingReader{r: c, max: s.Transcript}
	br := bufio.NewReaderSize(rec, 64<<10)
	for {
		req, e := http.ReadRequest(br)
		if e != nil {
			if len(rec.data) > 0 {
				sess.Emit(ctx, "http.malformed", "failure", nil, nil, model.Evidence{Kind: "http.raw", ContentType: "application/octet-stream", Data: rec.take()})
			}
			return
		}
		body, e := io.ReadAll(io.LimitReader(req.Body, s.RequestBytes+1))
		req.Body.Close()
		tooLarge := int64(len(body)) > s.RequestBytes
		if tooLarge {
			body = body[:s.RequestBytes]
		}
		attrs := map[string]any{"http.method": req.Method, "url.path": req.URL.EscapedPath(), "http.user_agent": req.UserAgent(), "http.host": req.Host, "body_truncated": tooLarge}
		evidence := []model.Evidence{{Kind: "http.raw", ContentType: "application/octet-stream", Data: rec.take()}}
		if len(body) > 0 {
			evidence = append(evidence, model.Evidence{Kind: "http.body", ContentType: req.Header.Get("Content-Type"), Data: body})
		}
		if !tooLarge {
			evidence = append(evidence, s.uploads(req.Header.Get("Content-Type"), body)...)
		}
		if e = sess.Emit(ctx, "http.request", "success", attrs, map[string]any{"headers": safeHeaders(req.Header), "query_keys": queryKeys(req)}, evidence...); e != nil {
			return
		}
		status, ct, response := s.route(req)
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), s.Persona.HTTP.Server, ct, len(response), response)
		return
	}
}

type recordingReader struct {
	r    io.Reader
	data []byte
	max  int64
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	left := r.max - int64(len(r.data))
	if left > 0 {
		keep := n
		if int64(keep) > left {
			keep = int(left)
		}
		r.data = append(r.data, p[:keep]...)
	}
	return n, e
}
func (r *recordingReader) take() []byte { b := append([]byte(nil), r.data...); r.data = nil; return b }
func (s *Server) route(r *http.Request) (int, string, string) {
	for _, x := range s.Persona.HTTP.Routes {
		if x.Path != r.URL.Path {
			continue
		}
		for _, m := range x.Methods {
			if strings.EqualFold(m, r.Method) {
				return x.Status, x.ContentType, x.Body
			}
		}
	}
	return http.StatusNotFound, "text/html; charset=utf-8", "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>"
}
func (s *Server) uploads(contentType string, body []byte) []model.Evidence {
	med, params, e := mime.ParseMediaType(contentType)
	if e != nil || med != "multipart/form-data" {
		return nil
	}
	mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	var out []model.Evidence
	for {
		p, e := mr.NextPart()
		if e != nil {
			break
		}
		if p.FileName() == "" {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(p, s.ArtifactBytes+1))
		if int64(len(b)) > s.ArtifactBytes {
			b = b[:s.ArtifactBytes]
		}
		out = append(out, model.Evidence{Kind: "artifact.upload", ContentType: p.Header.Get("Content-Type"), Filename: p.FileName(), Data: b})
	}
	return out
}
func safeHeaders(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
			continue
		}
		out[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	return out
}
func queryKeys(r *http.Request) []string {
	out := make([]string, 0, len(r.URL.Query()))
	for k := range r.URL.Query() {
		out = append(out, k)
	}
	return out
}
