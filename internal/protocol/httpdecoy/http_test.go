package httpdecoy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/ksahoo/fyke/internal/persona"
)

func TestRecordingReaderIsBounded(t *testing.T) {
	r := &recordingReader{r: bytes.NewReader([]byte("0123456789")), max: 4}
	b, _ := io.ReadAll(r)
	if string(b) != "0123456789" {
		t.Fatal("wrapped reader changed input")
	}
	if got := string(r.take()); got != "0123" {
		t.Fatalf("capture=%q", got)
	}
}

func TestConversationRouteStateAndEscaping(t *testing.T) {
	s := &Server{Persona: persona.Persona{Host: persona.Host{Hostname: "edge"}, HTTP: persona.HTTP{Routes: []persona.Route{
		{Path: "/login", Methods: []string{"POST"}, Status: 200, ContentType: "text/html", Body: "hello {{form.user}}", SetState: map[string]string{"user": "{{form.user}}"}},
		{PathPattern: "/admin/{page}", Methods: []string{"GET"}, Status: 200, ContentType: "text/html", Body: "{{state.user}}/{{path.page}}", RequireState: map[string]string{"user": "<admin>"}},
	}}}}
	login := httptest.NewRequest("POST", "http://example/login", bytes.NewBufferString("user=%3Cadmin%3E"))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	conv, _ := s.conversation(login)
	status, _, body, _ := s.route(login, []byte("user=%3Cadmin%3E"), conv)
	if status != 200 || body != "hello &lt;admin&gt;" {
		t.Fatalf("login=%d %q", status, body)
	}
	admin := httptest.NewRequest("GET", "http://example/admin/system", nil)
	status, _, body, _ = s.route(admin, nil, conv)
	if status != 200 || body != "&lt;admin&gt;/system" {
		t.Fatalf("admin=%d %q", status, body)
	}
}
