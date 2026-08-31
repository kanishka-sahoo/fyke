package sshdecoy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ksahoo/fyke/internal/emulator"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/persona"
	"github.com/ksahoo/fyke/internal/sensor"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	ID, Address, HostKey      string
	Persona                   persona.Persona
	Sink                      sensor.Sink
	Gate                      *sensor.AuthGate
	Limiter                   *sensor.Limiter
	Idle, Cap                 time.Duration
	Transcript, ArtifactBytes int64
}

func (s *Server) Serve(ctx context.Context) error {
	key, e := os.ReadFile(s.HostKey)
	if e != nil {
		return e
	}
	signer, e := ssh.ParsePrivateKey(key)
	if e != nil {
		return e
	}
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
		go s.handle(ctx, c, signer)
	}
}
func (s *Server) handle(parent context.Context, c net.Conn, signer ssh.Signer) {
	defer c.Close()
	c = sensor.WithIdle(c, s.Idle)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	release, e := s.Limiter.Acquire(host)
	if e != nil {
		return
	}
	defer release()
	sess := sensor.NewSession(s.ID, "ssh", s.Persona.ID, c, s.Sink, s.Transcript)
	ctx, cancel := context.WithTimeout(parent, s.Cap)
	defer cancel()
	go func() { <-ctx.Done(); _ = c.Close() }()
	cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-" + s.Persona.Host.SSHBanner, MaxAuthTries: 12}
	cfg.AddHostKey(signer)
	cfg.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		ok := s.Gate.Accept(host, "ssh", meta.User(), string(password))
		if err := sess.Emit(ctx, "authentication.attempt", outcome(ok), map[string]any{"username": meta.User(), "method": "password", "client_version": string(meta.ClientVersion())}, nil, model.Evidence{Kind: "credential.password", ContentType: "text/plain", Data: password}); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("permission denied")
		}
		return nil, nil
	}
	cfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		sum := sha256.Sum256(key.Marshal())
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		ok := s.Gate.Accept(host, "ssh", meta.User(), fp)
		if err := sess.Emit(ctx, "authentication.attempt", outcome(ok), map[string]any{"username": meta.User(), "method": "publickey", "fingerprint": fp, "key_type": key.Type()}, nil, model.Evidence{Kind: "credential.public_key", ContentType: "application/ssh-key", Data: ssh.MarshalAuthorizedKey(key)}); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("permission denied")
		}
		return nil, nil
	}
	cfg.KeyboardInteractiveCallback = func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, e := challenge(meta.User(), "Password authentication", []string{"Password: "}, []bool{false})
		if e != nil || len(answers) == 0 {
			return nil, errors.New("permission denied")
		}
		ok := s.Gate.Accept(host, "ssh", meta.User(), answers[0])
		if err := sess.Emit(ctx, "authentication.attempt", outcome(ok), map[string]any{"username": meta.User(), "method": "keyboard-interactive"}, nil, model.Evidence{Kind: "credential.password", ContentType: "text/plain", Data: []byte(answers[0])}); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("permission denied")
		}
		return nil, nil
	}
	conn, chans, requests, e := ssh.NewServerConn(c, cfg)
	if e != nil {
		return
	}
	defer conn.Close()
	if e = sess.Emit(ctx, "session.start", "success", map[string]any{"username": conn.User(), "client_version": string(conn.ClientVersion())}, nil); e != nil {
		return
	}
	defer sess.Emit(context.Background(), "session.end", "success", nil, nil)
	go ssh.DiscardRequests(requests)
	sh := emulator.NewShellWithSeed(s.Persona, conn.User(), sess.ID)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		channel, reqs, e := ch.Accept()
		if e != nil {
			continue
		}
		go s.session(ctx, sess, sh, channel, reqs)
	}
}
func (s *Server) session(ctx context.Context, sess *sensor.Session, sh *emulator.Shell, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			s.interactive(ctx, sess, sh, ch)
			return
		case "exec":
			var v struct{ Command string }
			if e := ssh.Unmarshal(req.Payload, &v); e != nil {
				req.Reply(false, nil)
				return
			}
			if strings.HasPrefix(strings.TrimSpace(v.Command), "scp ") {
				if e := sess.Emit(ctx, "ssh.scp", "failure", map[string]any{"rejected": true}, nil, model.Evidence{Kind: "command.arguments", ContentType: "text/plain", Data: []byte(v.Command)}); e != nil {
					return
				}
				req.Reply(false, nil)
				io.WriteString(ch, "scp: legacy SCP execution is disabled\n")
				return
			}
			req.Reply(true, nil)
			res := sh.Run(v.Command)
			if !waitResult(ctx, res.Delay) {
				return
			}
			if e := s.recordCommand(ctx, sess, v.Command, res); e != nil {
				return
			}
			io.WriteString(ch, strings.ReplaceAll(res.Output, "\r\n", "\n"))
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(res.ExitStatus)}))
			return
		case "subsystem":
			var v struct{ Name string }
			ssh.Unmarshal(req.Payload, &v)
			if v.Name != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.serveSFTP(ctx, sess, ch)
			return
		default:
			req.Reply(false, nil)
		}
	}
}
func (s *Server) interactive(ctx context.Context, sess *sensor.Session, sh *emulator.Shell, ch ssh.Channel) {
	io.WriteString(ch, "Linux "+s.Persona.Host.Hostname+" "+s.Persona.Host.Kernel+" x86_64\r\n\r\n")
	buf := make([]byte, 1)
	line := []byte{}
	cursor := 0
	history := []string{}
	historyAt := 0
	io.WriteString(ch, sh.Prompt())
	redraw := func() {
		io.WriteString(ch, "\r\x1b[2K"+sh.Prompt()+string(line))
		if back := len(line) - cursor; back > 0 {
			io.WriteString(ch, fmt.Sprintf("\x1b[%dD", back))
		}
	}
	for {
		if _, e := ch.Read(buf); e != nil {
			return
		}
		switch buf[0] {
		case '\r', '\n':
			io.WriteString(ch, "\r\n")
			input := string(line)
			if strings.TrimSpace(input) != "" {
				history = append(history, input)
				if len(history) > 100 {
					history = history[len(history)-100:]
				}
			}
			historyAt = len(history)
			line = nil
			cursor = 0
			res := sh.Run(input)
			if !waitResult(ctx, res.Delay) {
				return
			}
			if e := s.recordCommand(ctx, sess, input, res); e != nil {
				return
			}
			io.WriteString(ch, res.Output)
			if res.Exit {
				return
			}
			io.WriteString(ch, sh.Prompt())
		case 3: // Ctrl-C: cancel the current line, keep the session.
			line = nil
			cursor = 0
			io.WriteString(ch, "^C\r\n"+sh.Prompt())
		case 4: // Ctrl-D
			if len(line) == 0 {
				return
			}
		case 21: // Ctrl-U
			line = nil
			cursor = 0
			redraw()
		case 23: // Ctrl-W
			for cursor > 0 && line[cursor-1] == ' ' {
				line = append(line[:cursor-1], line[cursor:]...)
				cursor--
			}
			for cursor > 0 && line[cursor-1] != ' ' {
				line = append(line[:cursor-1], line[cursor:]...)
				cursor--
			}
			redraw()
		case 9: // Tab
			start := cursor
			for start > 0 && line[start-1] != ' ' {
				start--
			}
			prefix := string(line[start:cursor])
			completed := sh.Complete(prefix)
			if completed != prefix {
				replacement := []byte(completed)
				line = append(append(append([]byte{}, line[:start]...), replacement...), line[cursor:]...)
				cursor = start + len(replacement)
				redraw()
			}
		case 27: // Common ANSI cursor/history sequences.
			seq := make([]byte, 2)
			if _, e := io.ReadFull(ch, seq); e != nil {
				return
			}
			if seq[0] != '[' {
				continue
			}
			switch seq[1] {
			case 'A':
				if historyAt > 0 {
					historyAt--
					line = []byte(history[historyAt])
					cursor = len(line)
					redraw()
				}
			case 'B':
				if historyAt < len(history)-1 {
					historyAt++
					line = []byte(history[historyAt])
				} else {
					historyAt = len(history)
					line = nil
				}
				cursor = len(line)
				redraw()
			case 'C':
				if cursor < len(line) {
					cursor++
					io.WriteString(ch, "\x1b[C")
				}
			case 'D':
				if cursor > 0 {
					cursor--
					io.WriteString(ch, "\x1b[D")
				}
			}
		case 8, 127:
			if cursor > 0 {
				line = append(line[:cursor-1], line[cursor:]...)
				cursor--
				redraw()
			}
		default:
			if len(line) < 16<<10 {
				line = append(line, 0)
				copy(line[cursor+1:], line[cursor:])
				line[cursor] = buf[0]
				cursor++
				redraw()
			}
		}
	}
}
func (s *Server) recordCommand(ctx context.Context, sess *sensor.Session, input string, res emulator.Result) error {
	outcome := "success"
	if res.ExitStatus != 0 {
		outcome = "failure"
	}
	if e := sess.Emit(ctx, "command", outcome, map[string]any{"command": res.Command, "exit_status": res.ExitStatus, "unsupported_syntax": res.Unsupported, "emulation_gap": res.Gap, "observation": res.Observation, "urls": res.URLs}, nil, model.Evidence{Kind: "command.arguments", ContentType: "text/plain", Data: []byte(res.Arguments)}); e != nil {
		return e
	}
	if res.Gap != "" {
		if e := sess.Emit(ctx, "emulation.gap", "observed", map[string]any{"command": res.Command, "gap": res.Gap}, nil); e != nil {
			return e
		}
	}
	if b := sess.Transcript([]byte(input + "\n" + res.Output)); len(b) > 0 {
		if e := sess.Emit(ctx, "transcript.chunk", "success", nil, nil, model.Evidence{Kind: "transcript", ContentType: "text/plain", Data: b}); e != nil {
			return e
		}
	}
	return nil
}

func waitResult(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type quarantineFS struct {
	p     persona.Persona
	limit int64
	sess  *sensor.Session
	ctx   context.Context
	mu    sync.Mutex
}

func (f *quarantineFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	v, ok := f.p.Files[path.Clean("/"+strings.TrimPrefix(r.Filepath, "/"))]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.NewReader([]byte(v.Content)), nil
}
func (f *quarantineFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return &upload{limit: f.limit, name: path.Base(strings.ReplaceAll(r.Filepath, "\\", "/")), remotePath: r.Filepath, sess: f.sess, ctx: f.ctx}, nil
}
func (f *quarantineFS) Filecmd(r *sftp.Request) error {
	return errors.New("read-only emulated filesystem")
}
func (f *quarantineFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	clean := path.Clean("/" + strings.TrimPrefix(r.Filepath, "/"))
	if r.Method == "Stat" {
		v, ok := f.p.Files[clean]
		if !ok {
			return nil, os.ErrNotExist
		}
		return fileList{fakeInfo{name: path.Base(clean), size: int64(len(v.Content)), mode: 0444}}, nil
	}
	prefix := strings.TrimSuffix(clean, "/") + "/"
	seen := map[string]bool{}
	var list fileList
	for p, v := range f.p.Files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		name := strings.Split(strings.TrimPrefix(p, prefix), "/")[0]
		if seen[name] {
			continue
		}
		seen[name] = true
		mode := os.FileMode(0444)
		size := int64(len(v.Content))
		if strings.Contains(strings.TrimPrefix(p, prefix), "/") {
			mode = os.ModeDir | 0555
			size = 0
		}
		list = append(list, fakeInfo{name: name, size: size, mode: mode})
	}
	if len(list) == 0 && clean != "/" {
		return nil, os.ErrNotExist
	}
	return list, nil
}

type upload struct {
	mu               sync.Mutex
	data             []byte
	limit            int64
	name, remotePath string
	sess             *sensor.Session
	ctx              context.Context
	truncated        bool
}

func (u *upload) WriteAt(p []byte, off int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if off < 0 || off > u.limit {
		return 0, fmt.Errorf("artifact limit exceeded")
	}
	n := len(p)
	if off+int64(n) > u.limit {
		n = int(u.limit - off)
		u.truncated = true
	}
	need := int(off) + n
	if need > len(u.data) {
		u.data = append(u.data, make([]byte, need-len(u.data))...)
	}
	copy(u.data[int(off):], p[:n])
	if n < len(p) {
		return n, fmt.Errorf("artifact limit exceeded")
	}
	return n, nil
}
func (u *upload) Close() error {
	u.mu.Lock()
	b := append([]byte(nil), u.data...)
	u.mu.Unlock()
	return u.sess.Emit(u.ctx, "artifact.upload", "success", map[string]any{"path": u.remotePath, "truncated": u.truncated}, map[string]any{"subsystem": "sftp"}, model.Evidence{Kind: "artifact.upload", ContentType: "application/octet-stream", Filename: u.name, Data: b})
}

type fileList []os.FileInfo

func (l fileList) ListAt(dst []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[off:])
	if int(off)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

type fakeInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Now().Add(-48 * time.Hour) }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }
func (s *Server) serveSFTP(ctx context.Context, sess *sensor.Session, ch ssh.Channel) {
	fs := &quarantineFS{p: s.Persona, limit: s.ArtifactBytes, sess: sess, ctx: ctx}
	server := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs})
	sess.Emit(ctx, "sftp.start", "success", nil, nil)
	if e := server.Serve(); e != nil && e != io.EOF {
		sess.Emit(ctx, "sftp.error", "failure", map[string]any{"error": e.Error()}, nil)
	}
	server.Close()
}
func outcome(v bool) string {
	if v {
		return "success"
	}
	return "failure"
}
