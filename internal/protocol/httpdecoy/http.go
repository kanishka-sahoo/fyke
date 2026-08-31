package httpdecoy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"sync"
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
	conversationMu                          sync.Mutex
	conversations                           map[string]*conversation
}

type conversation struct {
	ID       string
	State    map[string]string
	LastSeen time.Time
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
	for requestCount := 0; requestCount < 25; requestCount++ {
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
		conv, setCookie := s.conversation(req)
		attrs := map[string]any{"http.method": req.Method, "url.path": req.URL.EscapedPath(), "http.user_agent": req.UserAgent(), "http.host": req.Host, "body_truncated": tooLarge, "web_conversation_id": conv.ID}
		evidence := []model.Evidence{{Kind: "http.raw", ContentType: "application/octet-stream", Data: rec.take()}}
		if len(body) > 0 {
			evidence = append(evidence, model.Evidence{Kind: "http.body", ContentType: req.Header.Get("Content-Type"), Data: body})
		}
		if !tooLarge {
			evidence = append(evidence, s.uploads(req.Header.Get("Content-Type"), body)...)
		}
		if e = sess.Emit(ctx, "http.request", "success", attrs, map[string]any{"headers": safeHeaders(req.Header), "query_keys": queryKeys(req), "form_keys": formKeys(req.Header.Get("Content-Type"), body), "web_conversation_id": conv.ID}, evidence...); e != nil {
			return
		}
		status, ct, response, delay := s.route(req, body, conv)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		closeConnection := req.Close || requestCount == 24
		connection := "keep-alive"
		if closeConnection {
			connection = "close"
		}
		responseBody := response
		if req.Method == http.MethodHead {
			responseBody = ""
		}
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nX-Content-Type-Options: nosniff\r\nConnection: %s\r\n", status, http.StatusText(status), s.Persona.HTTP.Server, time.Now().UTC().Format(http.TimeFormat), ct, len(response), connection)
		if setCookie {
			secure := ""
			if s.Protocol == "https" {
				secure = "; Secure"
			}
			fmt.Fprintf(c, "Set-Cookie: FYKECID=%s; Path=/; HttpOnly; SameSite=Lax%s\r\n", conv.ID, secure)
		}
		fmt.Fprintf(c, "\r\n%s", responseBody)
		if closeConnection {
			return
		}
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
func (s *Server) route(r *http.Request, body []byte, conv *conversation) (int, string, string, time.Duration) {
	for _, x := range s.Persona.HTTP.Routes {
		pattern := x.Path
		if x.PathPattern != "" {
			pattern = x.PathPattern
		}
		params, matches := matchPath(pattern, r.URL.Path)
		if !matches || !matchesMap(x.Query, r.URL.Query(), nil) || !matchesMap(x.Headers, nil, r.Header) {
			continue
		}
		s.conversationMu.Lock()
		stateMatches := true
		for k, v := range x.RequireState {
			if conv.State[k] != v {
				stateMatches = false
				break
			}
		}
		s.conversationMu.Unlock()
		if !stateMatches {
			continue
		}
		for _, m := range x.Methods {
			if strings.EqualFold(m, r.Method) {
				form := formValues(r.Header.Get("Content-Type"), body)
				s.conversationMu.Lock()
				for k, v := range x.SetState {
					conv.State[k] = stateValue(v, params, form)
				}
				state := make(map[string]string, len(conv.State))
				for k, v := range conv.State {
					state[k] = v
				}
				s.conversationMu.Unlock()
				return x.Status, x.ContentType, render(x.Body, x.ContentType, s.Persona, state, params, form), time.Duration(x.DelayMS) * time.Millisecond
			}
		}
	}
	return http.StatusNotFound, "text/html; charset=utf-8", "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>", 0
}

func stateValue(value string, pathValues, form map[string]string) string {
	for k, v := range pathValues {
		value = strings.ReplaceAll(value, "{{path."+k+"}}", v)
	}
	for k, v := range form {
		value = strings.ReplaceAll(value, "{{form."+k+"}}", v)
	}
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func (s *Server) conversation(r *http.Request) (*conversation, bool) {
	now := time.Now()
	id := ""
	if c, e := r.Cookie("FYKECID"); e == nil && len(c.Value) == 32 {
		if _, e = hex.DecodeString(c.Value); e == nil {
			id = c.Value
		}
	}
	s.conversationMu.Lock()
	defer s.conversationMu.Unlock()
	if s.conversations == nil {
		s.conversations = map[string]*conversation{}
	}
	if existing := s.conversations[id]; existing != nil && now.Sub(existing.LastSeen) < 2*time.Hour {
		existing.LastSeen = now
		return existing, false
	}
	if len(s.conversations) >= 4096 {
		for key, v := range s.conversations {
			if now.Sub(v.LastSeen) >= 2*time.Hour {
				delete(s.conversations, key)
			}
		}
		if len(s.conversations) >= 4096 {
			oldestKey := ""
			var oldest time.Time
			for key, v := range s.conversations {
				if oldestKey == "" || v.LastSeen.Before(oldest) {
					oldestKey, oldest = key, v.LastSeen
				}
			}
			delete(s.conversations, oldestKey)
		}
	}
	random := make([]byte, 16)
	if _, e := rand.Read(random); e != nil {
		sum := time.Now().UnixNano()
		for i := range random {
			random[i] = byte(sum >> uint(i%8*8))
		}
	}
	id = hex.EncodeToString(random)
	conv := &conversation{ID: id, State: map[string]string{}, LastSeen: now}
	s.conversations[id] = conv
	return conv, true
}

func matchPath(pattern, actual string) (map[string]string, bool) {
	params := map[string]string{}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if !strings.HasPrefix(actual, prefix) {
			return nil, false
		}
		params["wildcard"] = strings.TrimPrefix(actual, prefix)
		return params, true
	}
	p := strings.Split(strings.Trim(pattern, "/"), "/")
	a := strings.Split(strings.Trim(actual, "/"), "/")
	if len(p) != len(a) {
		return nil, false
	}
	for i := range p {
		if strings.HasPrefix(p[i], "{") && strings.HasSuffix(p[i], "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(p[i], "{"), "}")
			if name == "" || a[i] == "" {
				return nil, false
			}
			params[name] = a[i]
		} else if p[i] != a[i] {
			return nil, false
		}
	}
	return params, true
}

func matchesMap(want map[string]string, query map[string][]string, headers http.Header) bool {
	for k, v := range want {
		got := ""
		if query != nil {
			if values := query[k]; len(values) > 0 {
				got = values[0]
			}
		} else {
			got = headers.Get(k)
		}
		if got != v {
			return false
		}
	}
	return true
}

func render(body, contentType string, p persona.Persona, state, pathValues, form map[string]string) string {
	escape := func(v string) string {
		if strings.Contains(strings.ToLower(contentType), "json") {
			b, _ := json.Marshal(v)
			if len(b) >= 2 {
				return string(b[1 : len(b)-1])
			}
		}
		return html.EscapeString(v)
	}
	values := map[string]string{"persona.host.hostname": p.Host.Hostname, "persona.host.os": p.Host.OS}
	for k, v := range state {
		values["state."+k] = v
	}
	for k, v := range pathValues {
		values["path."+k] = v
	}
	for k, v := range form {
		values["form."+k] = v
	}
	for k, v := range values {
		body = strings.ReplaceAll(body, "{{"+k+"}}", escape(v))
	}
	return body
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
	sort.Strings(out)
	return out
}

func formValues(contentType string, body []byte) map[string]string {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "application/x-www-form-urlencoded" {
		return map[string]string{}
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func formKeys(contentType string, body []byte) []string {
	values := formValues(contentType, body)
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	media, params, e := mime.ParseMediaType(contentType)
	if e == nil && media == "multipart/form-data" {
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		seen := map[string]bool{}
		for {
			part, partErr := reader.NextPart()
			if partErr != nil {
				break
			}
			name := part.FormName()
			if name != "" && !seen[name] {
				out = append(out, name)
				seen[name] = true
			}
		}
	}
	sort.Strings(out)
	return out
}
