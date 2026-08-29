// Package emulator provides deterministic stateful decoys. It intentionally has
// no command-execution adapter: input is parsed and interpreted only against a
// read-only persona plus a per-session in-memory overlay.
package emulator

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ksahoo/fyke/internal/persona"
)

type Result struct {
	Output      string
	Command     string
	Arguments   string
	Unsupported bool
	URLs        []string
	Exit        bool
}
type Shell struct {
	persona persona.Persona
	user    persona.User
	cwd     string
	overlay map[string]*string
	now     func() time.Time
}

func NewShell(p persona.Persona, user string) *Shell {
	u, ok := p.User(user)
	if !ok {
		u = persona.User{Name: user, UID: 1000, Home: "/home/" + user, Shell: "/bin/bash"}
	}
	return &Shell{persona: p, user: u, cwd: u.Home, overlay: map[string]*string{}, now: time.Now}
}
func (s *Shell) Prompt() string {
	sig := "$"
	if s.user.UID == 0 {
		sig = "#"
	}
	where := s.cwd
	if strings.HasPrefix(where, s.user.Home) {
		where = "~" + strings.TrimPrefix(where, s.user.Home)
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.user.Name, s.persona.Host.Hostname, where, sig)
}
func (s *Shell) Run(line string) Result {
	line = strings.TrimSpace(line)
	if line == "" {
		return Result{}
	}
	args, unsupported := tokenize(line)
	if unsupported || len(args) == 0 {
		return Result{Output: "-bash: syntax not supported\r\n", Unsupported: true, Arguments: line}
	}
	r := Result{Command: path.Base(args[0]), Arguments: strings.Join(args[1:], " ")}
	switch r.Command {
	case "exit", "logout":
		r.Exit = true
	case "pwd":
		r.Output = s.cwd + "\r\n"
	case "whoami":
		r.Output = s.user.Name + "\r\n"
	case "hostname":
		r.Output = s.persona.Host.Hostname + "\r\n"
	case "id":
		r.Output = fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s)\r\n", s.user.UID, s.user.Name, s.user.UID, s.user.Name, s.user.UID, s.user.Name)
	case "uname":
		if contains(args, "-a") {
			r.Output = fmt.Sprintf("Linux %s %s #1 SMP Debian x86_64 GNU/Linux\r\n", s.persona.Host.Hostname, s.persona.Host.Kernel)
		} else {
			r.Output = "Linux\r\n"
		}
	case "uptime":
		up := s.now().Sub(s.persona.Host.BootedAt)
		if up < 0 {
			up = 37 * time.Hour
		}
		r.Output = fmt.Sprintf(" %s up %d days, %02d:%02d,  1 user,  load average: 0.08, 0.04, 0.01\r\n", s.now().Format("15:04:05"), int(up.Hours()/24), int(up.Hours())%24, int(up.Minutes())%60)
	case "date":
		r.Output = s.now().Format("Mon Jan 2 15:04:05 MST 2006") + "\r\n"
	case "cd":
		target := s.user.Home
		if len(args) > 1 {
			target = s.resolve(args[1])
		}
		if s.isDir(target) {
			s.cwd = target
		} else {
			r.Output = "-bash: cd: " + safeArg(args, 1) + ": No such file or directory\r\n"
		}
	case "ls":
		target := s.cwd
		for _, a := range args[1:] {
			if !strings.HasPrefix(a, "-") {
				target = s.resolve(a)
			}
		}
		names := s.list(target)
		if names == nil {
			r.Output = "ls: cannot access '" + safeArg(args, len(args)-1) + "': No such file or directory\r\n"
		} else {
			r.Output = strings.Join(names, "  ") + "\r\n"
		}
	case "cat", "head", "tail":
		if len(args) < 2 {
			r.Output = ""
			break
		}
		for _, name := range args[1:] {
			if strings.HasPrefix(name, "-") {
				continue
			}
			if body, ok := s.read(s.resolve(name)); ok {
				r.Output += strings.ReplaceAll(body, "\n", "\r\n")
				if !strings.HasSuffix(r.Output, "\r\n") {
					r.Output += "\r\n"
				}
			} else {
				r.Output += r.Command + ": " + name + ": No such file or directory\r\n"
			}
		}
	case "touch":
		for _, name := range args[1:] {
			v := ""
			s.overlay[s.resolve(name)] = &v
		}
	case "mkdir":
		for _, name := range args[1:] {
			if strings.HasPrefix(name, "-") {
				continue
			}
			v := ""
			s.overlay[path.Clean(s.resolve(name))+"/"] = &v
		}
	case "rm":
		for _, name := range args[1:] {
			if strings.HasPrefix(name, "-") {
				continue
			}
			p := s.resolve(name)
			nilv := (*string)(nil)
			s.overlay[p] = nilv
		}
	case "echo":
		r.Output = strings.Join(args[1:], " ") + "\r\n"
	case "ps":
		r.Output = "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 systemd\r\n  412 ?        00:00:00 sshd\r\n 1337 pts/0    00:00:00 bash\r\n"
	case "curl", "wget":
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
				r.URLs = append(r.URLs, a)
			}
		}
		r.Output = r.Command + ": unable to resolve host address\r\n"
	case "sudo":
		r.Output = "[sudo] password for " + s.user.Name + ": \r\nsudo: a password is required\r\n"
	case "help":
		r.Output = "GNU bash, version 5.2.15(1)-release. Type `help name' for more information.\r\n"
	default:
		r.Output = r.Command + ": command not found\r\n"
	}
	return r
}
func tokenize(s string) ([]string, bool) {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if strings.ContainsRune(";|&><`$(){}\n\r", r) {
			return nil, true
		}
		if unicode.IsSpace(r) {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		} else {
			b.WriteRune(r)
		}
	}
	if quote != 0 || escaped {
		return nil, true
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out, false
}
func (s *Shell) resolve(v string) string {
	if v == "~" {
		return s.user.Home
	}
	if strings.HasPrefix(v, "~/") {
		v = path.Join(s.user.Home, v[2:])
	}
	if !strings.HasPrefix(v, "/") {
		v = path.Join(s.cwd, v)
	}
	return path.Clean(v)
}
func (s *Shell) read(p string) (string, bool) {
	if v, ok := s.overlay[p]; ok {
		if v == nil {
			return "", false
		}
		return *v, true
	}
	f, ok := s.persona.Files[p]
	return f.Content, ok
}
func (s *Shell) isDir(dir string) bool {
	dir = strings.TrimSuffix(path.Clean(dir), "/") + "/"
	if dir == "//" || dir == "/" {
		return true
	}
	for p := range s.persona.Files {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	for p, v := range s.overlay {
		if v != nil && strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}
func (s *Shell) list(dir string) []string {
	dir = path.Clean(dir)
	if !s.isDir(dir) {
		return nil
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	set := map[string]bool{}
	for p := range s.persona.Files {
		if strings.HasPrefix(p, prefix) {
			set[strings.Split(strings.TrimPrefix(p, prefix), "/")[0]] = true
		}
	}
	for p, v := range s.overlay {
		if v != nil && strings.HasPrefix(p, prefix) {
			set[strings.Split(strings.TrimPrefix(p, prefix), "/")[0]] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func contains(v []string, q string) bool {
	for _, x := range v {
		if x == q {
			return true
		}
	}
	return false
}
func safeArg(v []string, i int) string {
	if i >= 0 && i < len(v) {
		return strconv.QuoteToASCII(v[i])[1 : len(strconv.QuoteToASCII(v[i]))-1]
	}
	return ""
}
