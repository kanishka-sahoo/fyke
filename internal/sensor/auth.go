package sensor

import (
	"sync"
	"time"

	"github.com/ksahoo/fyke/internal/persona"
)

type attemptKey struct{ source, protocol string }
type attemptWindow struct {
	started  time.Time
	failures int
}
type AuthGate struct {
	mu      sync.Mutex
	persona persona.Persona
	windows map[attemptKey]attemptWindow
	now     func() time.Time
}

func NewAuthGate(p persona.Persona) *AuthGate {
	return &AuthGate{persona: p, windows: map[attemptKey]attemptWindow{}, now: time.Now}
}

// Accept returns true for configured honey credentials, or on the third failed
// attempt for the same source/protocol in a rolling ten-minute window.
func (g *AuthGate) Accept(source, protocol, user, password string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.persona.PasswordAccepted(user, password) {
		delete(g.windows, attemptKey{source, protocol})
		return true
	}
	k := attemptKey{source, protocol}
	w := g.windows[k]
	if w.started.IsZero() || g.now().Sub(w.started) > 10*time.Minute {
		w = attemptWindow{started: g.now()}
	}
	w.failures++
	if w.failures >= 3 {
		delete(g.windows, k)
		return true
	}
	g.windows[k] = w
	return false
}
