package telnet

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/emulator"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/persona"
	"github.com/ksahoo/fyke/internal/sensor"
)

const (
	iac  = 255
	will = 251
	wont = 252
	do   = 253
	dont = 254
	sb   = 250
	se   = 240
)

type Server struct {
	ID, Address string
	Persona     persona.Persona
	Sink        sensor.Sink
	Gate        *sensor.AuthGate
	Limiter     *sensor.Limiter
	Idle, Cap   time.Duration
	Transcript  int64
}

func (s *Server) Serve(ctx context.Context) error {
	ln, e := net.Listen("tcp", s.Address)
	if e != nil {
		return e
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
func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	c = sensor.WithIdle(c, s.Idle)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	release, e := s.Limiter.Acquire(host)
	if e != nil {
		return
	}
	defer release()
	sess := sensor.NewSession(s.ID, "telnet", s.Persona.ID, c, s.Sink, s.Transcript)
	ctx, cancel := context.WithTimeout(ctx, s.Cap)
	defer cancel()
	go func() { <-ctx.Done(); _ = c.Close() }()
	if e = sess.Emit(ctx, "session.start", "success", nil, nil); e != nil {
		return
	}
	defer sess.Emit(context.Background(), "session.end", "success", nil, nil)
	c.Write([]byte{iac, will, 1, iac, will, 3, iac, do, 31})
	io.WriteString(c, "\r\n"+s.Persona.Host.TelnetBanner+"\r\nlogin: ")
	r := newReader(c)
	user, e := r.line(128)
	if e != nil {
		return
	}
	io.WriteString(c, "Password: ")
	pass, e := r.line(256)
	if e != nil {
		return
	}
	accepted := s.Gate.Accept(host, "telnet", user, pass)
	if e = sess.Emit(ctx, "authentication.attempt", outcome(accepted), map[string]any{"username": user}, nil, model.Evidence{Kind: "credential.password", ContentType: "text/plain", Data: []byte(pass)}); e != nil {
		return
	}
	if !accepted {
		io.WriteString(c, "\r\nLogin incorrect\r\n")
		return
	}
	io.WriteString(c, "\r\nLast login: "+time.Now().Add(-19*time.Hour).Format(time.ANSIC)+" from 10.0.0.12\r\n")
	sh := emulator.NewShellWithSeed(s.Persona, user, sess.ID)
	for {
		io.WriteString(c, sh.Prompt())
		line, e := r.line(16 << 10)
		if e != nil {
			return
		}
		res := sh.Run(line)
		if res.Delay > 0 {
			timer := time.NewTimer(res.Delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		ev := []model.Evidence{{Kind: "command.arguments", ContentType: "text/plain", Data: []byte(res.Arguments)}}
		commandOutcome := "success"
		if res.ExitStatus != 0 {
			commandOutcome = "failure"
		}
		if e = sess.Emit(ctx, "command", commandOutcome, map[string]any{"command": res.Command, "exit_status": res.ExitStatus, "unsupported_syntax": res.Unsupported, "emulation_gap": res.Gap, "observation": res.Observation, "urls": res.URLs}, nil, ev...); e != nil {
			return
		}
		if res.Gap != "" {
			if e = sess.Emit(ctx, "emulation.gap", "observed", map[string]any{"command": res.Command, "gap": res.Gap}, nil); e != nil {
				return
			}
		}
		if b := sess.Transcript([]byte(line + "\n" + res.Output)); len(b) > 0 {
			if e = sess.Emit(ctx, "transcript.chunk", "success", nil, nil, model.Evidence{Kind: "transcript", ContentType: "text/plain", Data: b}); e != nil {
				return
			}
		}
		io.WriteString(c, res.Output)
		if res.Exit {
			return
		}
	}
}

type reader struct {
	r     *bufio.Reader
	state byte
}

func newReader(r io.Reader) *reader { return &reader{r: bufio.NewReaderSize(r, 4096)} }
func (r *reader) line(max int) (string, error) {
	var b strings.Builder
	for b.Len() < max {
		x, e := r.r.ReadByte()
		if e != nil {
			return "", e
		}
		if x == iac {
			cmd, e := r.r.ReadByte()
			if e != nil {
				return "", e
			}
			if cmd == iac {
				b.WriteByte(iac)
				continue
			}
			if cmd == sb {
				for {
					v, e := r.r.ReadByte()
					if e != nil {
						return "", e
					}
					if v == iac {
						v, e = r.r.ReadByte()
						if e != nil {
							return "", e
						}
						if v == se {
							break
						}
					}
				}
			} else if cmd == will || cmd == wont || cmd == do || cmd == dont {
				if _, e = r.r.ReadByte(); e != nil {
					return "", e
				}
			}
			continue
		}
		if x == '\n' {
			return strings.TrimSuffix(b.String(), "\r"), nil
		}
		if x != 0 {
			b.WriteByte(x)
		}
	}
	return "", errors.New("telnet line too long")
}
func outcome(v bool) string {
	if v {
		return "success"
	}
	return "failure"
}
