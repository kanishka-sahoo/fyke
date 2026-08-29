package sensor

import (
	"github.com/ksahoo/fyke/internal/persona"
	"testing"
)

func TestAuthGateHoneyOrThirdAttempt(t *testing.T) {
	g := NewAuthGate(persona.Persona{HoneyCredentials: []persona.Credential{{Username: "honey", Password: "secret"}}})
	if !g.Accept("1.2.3.4", "ssh", "honey", "secret") {
		t.Fatal("honey credential rejected")
	}
	if g.Accept("5.6.7.8", "ssh", "root", "a") || g.Accept("5.6.7.8", "ssh", "root", "b") {
		t.Fatal("accepted before third failure")
	}
	if !g.Accept("5.6.7.8", "ssh", "root", "c") {
		t.Fatal("third attempt rejected")
	}
	if g.Accept("5.6.7.8", "telnet", "root", "d") {
		t.Fatal("protocol windows were not isolated")
	}
}
func TestLimiterPerSource(t *testing.T) {
	l := NewLimiter(2, 1)
	release, e := l.Acquire("1.1.1.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = l.Acquire("1.1.1.1"); e == nil {
		t.Fatal("source limit ignored")
	}
	if other, e := l.Acquire("2.2.2.2"); e != nil {
		t.Fatal(e)
	} else {
		other()
	}
	release()
	if _, e = l.Acquire("1.1.1.1"); e != nil {
		t.Fatal("release failed")
	}
}
