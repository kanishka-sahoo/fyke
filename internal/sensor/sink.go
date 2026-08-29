package sensor

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ksahoo/fyke/internal/model"
)

type Sink interface {
	Emit(context.Context, model.Event) error
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}
func WithIdle(c net.Conn, d time.Duration) net.Conn {
	if d <= 0 {
		return c
	}
	return &idleConn{Conn: c, idle: d}
}

type Session struct {
	ID            string
	SensorID      string
	Protocol      string
	Persona       string
	Source        model.Endpoint
	Destination   model.Endpoint
	sink          Sink
	mu            sync.Mutex
	sequence      uint64
	transcript    int64
	maxTranscript int64
}

func NewSession(sensorID, protocol, persona string, c net.Conn, sink Sink, maxTranscript int64) *Session {
	src := endpoint(c.RemoteAddr())
	dst := endpoint(c.LocalAddr())
	return &Session{ID: model.NewUUIDv7(time.Now()), SensorID: sensorID, Protocol: protocol, Persona: persona, Source: src, Destination: dst, sink: sink, maxTranscript: maxTranscript}
}
func endpoint(a net.Addr) model.Endpoint {
	host, port, e := net.SplitHostPort(a.String())
	if e != nil {
		return model.Endpoint{IP: a.String()}
	}
	n, _ := strconv.ParseUint(port, 10, 16)
	return model.Endpoint{IP: host, Port: uint16(n)}
}
func (s *Session) Emit(ctx context.Context, typ, outcome string, attrs, protocol map[string]any, evidence ...model.Evidence) error {
	s.mu.Lock()
	s.sequence++
	seq := s.sequence
	s.mu.Unlock()
	e := model.Event{SensorID: s.SensorID, SessionID: s.ID, Sequence: seq, Source: s.Source, Destination: s.Destination, Protocol: s.Protocol, Type: typ, Outcome: outcome, Persona: s.Persona, Attributes: attrs, ProtocolData: protocol, Evidence: evidence}
	if err := e.Normalize(time.Now()); err != nil {
		return err
	}
	return s.sink.Emit(ctx, e)
}
func (s *Session) Transcript(data []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	left := s.maxTranscript - s.transcript
	if left <= 0 {
		return nil
	}
	if int64(len(data)) > left {
		data = data[:left]
	}
	s.transcript += int64(len(data))
	return data
}

type Limiter struct {
	mu                              sync.Mutex
	global, maxGlobal, maxPerSource int
	sources                         map[string]int
}

func NewLimiter(global, perSource int) *Limiter {
	return &Limiter{maxGlobal: global, maxPerSource: perSource, sources: map[string]int{}}
}
func (l *Limiter) Acquire(ip string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global >= l.maxGlobal {
		return nil, fmt.Errorf("global session limit reached")
	}
	if l.sources[ip] >= l.maxPerSource {
		return nil, fmt.Errorf("source session limit reached")
	}
	l.sources[ip]++
	l.global++
	once := sync.Once{}
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.global--
			l.sources[ip]--
			if l.sources[ip] == 0 {
				delete(l.sources, ip)
			}
			l.mu.Unlock()
		})
	}, nil
}
