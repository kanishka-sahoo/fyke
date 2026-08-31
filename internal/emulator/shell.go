// Package emulator provides deterministic, stateful decoys. It intentionally
// has no command execution or network adapter: input is interpreted only
// against a persona and a per-session in-memory overlay.
package emulator

import (
	"fmt"
	"hash/fnv"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	ExitStatus  int
	Gap         string
	Observation string
	Delay       time.Duration
}

type Shell struct {
	mu         sync.Mutex
	persona    persona.Persona
	user       persona.User
	cwd        string
	overlay    map[string]*string
	env        map[string]string
	lastStatus int
	seed       uint64
	now        func() time.Time
}

func NewShell(p persona.Persona, user string) *Shell { return NewShellWithSeed(p, user, "") }

func NewShellWithSeed(p persona.Persona, user, sessionID string) *Shell {
	u, ok := p.User(user)
	if !ok {
		u = persona.User{Name: user, UID: 1000, Home: "/home/" + user, Shell: "/bin/bash"}
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(p.ID + "\x00" + user + "\x00" + sessionID))
	env := map[string]string{"HOME": u.Home, "USER": u.Name, "LOGNAME": u.Name, "SHELL": u.Shell, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "PWD": u.Home}
	for k, v := range p.Shell.Environment {
		env[k] = v
	}
	return &Shell{persona: p, user: u, cwd: u.Home, overlay: map[string]*string{}, env: env, seed: h.Sum64(), now: time.Now}
}

func (s *Shell) Prompt() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prompt()
}

// Complete returns a bounded completion from the virtual command and file
// namespace. It never consults the host filesystem or PATH.
func (s *Shell) Complete(prefix string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var candidates []string
	for _, name := range strings.Fields("cat cd curl date df echo env find free grep head hostname id ip ls mkdir ps pwd rm ss systemctl tail touch uname uptime wc wget whoami") {
		if strings.HasPrefix(name, prefix) {
			candidates = append(candidates, name)
		}
	}
	for _, name := range s.list(s.cwd) {
		if strings.HasPrefix(name, prefix) {
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 1 {
		return candidates[0]
	}
	return prefix
}

func (s *Shell) prompt() string {
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

// Run parses a deliberately bounded shell grammar: quoting, environment
// expansion, globs, sequencing, conditionals, pipelines, and redirection.
// Substitution, loops, functions, jobs, arithmetic, and executable scripts are
// rejected and reported as emulation gaps.
func (s *Shell) Run(line string) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	line = strings.TrimSpace(line)
	if line == "" {
		return Result{ExitStatus: s.lastStatus}
	}
	tokens, err := s.lex(line)
	if err != nil {
		r := Result{Output: "-bash: " + err.Error() + "\r\n", Arguments: line, Unsupported: true, ExitStatus: 2, Gap: "unsupported shell syntax"}
		s.lastStatus = r.ExitStatus
		return r
	}
	r := s.eval(tokens)
	if r.Arguments == "" {
		r.Arguments = line
	}
	s.lastStatus = r.ExitStatus
	return r
}

type shellToken struct {
	text string
	op   bool
}

func (s *Shell) lex(line string) ([]shellToken, error) {
	if strings.Contains(line, "`") || strings.Contains(line, "$(") || strings.ContainsAny(line, "\n\r") {
		return nil, fmt.Errorf("syntax not supported")
	}
	var out []shellToken
	var b strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, shellToken{text: b.String()})
			b.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := rune(line[i])
		if escaped {
			b.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			if c == '$' && quote == '"' {
				value, n, ok := s.expand(line[i:])
				if ok {
					b.WriteString(value)
					i += n - 1
					continue
				}
			}
			b.WriteRune(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if unicode.IsSpace(c) {
			flush()
			continue
		}
		if c == '$' {
			value, n, ok := s.expand(line[i:])
			if !ok {
				return nil, fmt.Errorf("bad substitution")
			}
			b.WriteString(value)
			i += n - 1
			continue
		}
		if strings.ContainsRune("(){}", c) {
			return nil, fmt.Errorf("syntax not supported")
		}
		if strings.ContainsRune(";|&><", c) {
			flush()
			op := string(c)
			if i+1 < len(line) {
				next := line[i+1]
				if (c == '&' && next == '&') || (c == '|' && next == '|') || (c == '>' && next == '>') {
					op += string(next)
					i++
				}
			}
			if op == "&" {
				return nil, fmt.Errorf("job control is not supported")
			}
			out = append(out, shellToken{text: op, op: true})
			continue
		}
		b.WriteRune(c)
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return out, nil
}

func (s *Shell) expand(v string) (string, int, bool) {
	if strings.HasPrefix(v, "$?") {
		return strconv.Itoa(s.lastStatus), 2, true
	}
	if strings.HasPrefix(v, "${") {
		i := strings.IndexByte(v, '}')
		if i < 3 {
			return "", 0, false
		}
		name := v[2:i]
		if !validEnv(name) {
			return "", 0, false
		}
		return s.env[name], i + 1, true
	}
	i := 1
	for i < len(v) && (v[i] == '_' || unicode.IsLetter(rune(v[i])) || (i > 1 && unicode.IsDigit(rune(v[i])))) {
		i++
	}
	if i == 1 {
		return "", 0, false
	}
	return s.env[v[1:i]], i, true
}

func validEnv(v string) bool {
	if v == "" {
		return false
	}
	for i, c := range v {
		if c != '_' && !unicode.IsLetter(c) && !(i > 0 && unicode.IsDigit(c)) {
			return false
		}
	}
	return true
}

func (s *Shell) eval(tokens []shellToken) Result {
	var total Result
	start := 0
	previous := ";"
	for start < len(tokens) {
		end := start
		for end < len(tokens) && !(tokens[end].op && (tokens[end].text == ";" || tokens[end].text == "&&" || tokens[end].text == "||")) {
			end++
		}
		shouldRun := previous == ";" || (previous == "&&" && total.ExitStatus == 0) || (previous == "||" && total.ExitStatus != 0)
		if shouldRun {
			r := s.pipeline(tokens[start:end])
			total.Output += r.Output
			total.Command, total.Arguments, total.ExitStatus = r.Command, r.Arguments, r.ExitStatus
			total.Unsupported = total.Unsupported || r.Unsupported
			total.URLs = append(total.URLs, r.URLs...)
			total.Exit = total.Exit || r.Exit
			if r.Gap != "" {
				total.Gap = r.Gap
			}
			if r.Observation != "" {
				total.Observation = r.Observation
			}
			total.Delay += r.Delay
		}
		if end == len(tokens) {
			break
		}
		previous, start = tokens[end].text, end+1
	}
	return total
}

func (s *Shell) pipeline(tokens []shellToken) Result {
	var combined Result
	start := 0
	stdin := ""
	for start <= len(tokens) {
		end := start
		for end < len(tokens) && !(tokens[end].op && tokens[end].text == "|") {
			end++
		}
		argv, input, output, appendMode, err := s.argv(tokens[start:end])
		if err != nil {
			return Result{Output: "-bash: " + err.Error() + "\r\n", Unsupported: true, ExitStatus: 2, Gap: "invalid redirection"}
		}
		if input != "" {
			body, ok := s.read(s.resolve(input))
			if !ok {
				return Result{Output: "-bash: " + input + ": No such file or directory\r\n", ExitStatus: 1}
			}
			stdin = body
		}
		r := s.command(argv, stdin)
		if output != "" {
			body := strings.ReplaceAll(r.Output, "\r\n", "\n")
			p := s.resolve(output)
			if appendMode {
				if old, ok := s.read(p); ok {
					body = old + body
				}
			}
			s.overlay[p] = &body
			r.Output = ""
		}
		combined.Command, combined.Arguments, combined.Output, combined.ExitStatus = r.Command, r.Arguments, r.Output, r.ExitStatus
		combined.Unsupported = combined.Unsupported || r.Unsupported
		combined.URLs = append(combined.URLs, r.URLs...)
		combined.Exit = combined.Exit || r.Exit
		combined.Delay += r.Delay
		if r.Gap != "" {
			combined.Gap = r.Gap
		}
		if r.Observation != "" {
			combined.Observation = r.Observation
		}
		stdin = strings.ReplaceAll(r.Output, "\r\n", "\n")
		if end == len(tokens) {
			return combined
		}
		start = end + 1
	}
	return combined
}

func (s *Shell) argv(tokens []shellToken) (argv []string, input, output string, appendMode bool, err error) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].op {
			if tokens[i].text != "<" && tokens[i].text != ">" && tokens[i].text != ">>" {
				return nil, "", "", false, fmt.Errorf("syntax not supported")
			}
			if i+1 >= len(tokens) || tokens[i+1].op {
				return nil, "", "", false, fmt.Errorf("missing redirection target")
			}
			if tokens[i].text == "<" {
				input = tokens[i+1].text
			} else {
				output, appendMode = tokens[i+1].text, tokens[i].text == ">>"
			}
			i++
			continue
		}
		argv = append(argv, s.glob(tokens[i].text)...)
	}
	return
}

func (s *Shell) glob(v string) []string {
	if !strings.ContainsAny(v, "*?") {
		return []string{v}
	}
	dir, pattern := path.Split(s.resolve(v))
	names := s.list(strings.TrimSuffix(dir, "/"))
	var out []string
	for _, name := range names {
		if ok, _ := path.Match(pattern, name); ok {
			if strings.Contains(v, "/") {
				out = append(out, path.Join(dir, name))
			} else {
				out = append(out, name)
			}
		}
	}
	if len(out) == 0 {
		return []string{v}
	}
	return out
}

func (s *Shell) command(args []string, stdin string) Result {
	if len(args) == 0 {
		return Result{}
	}
	r := Result{Command: path.Base(args[0]), Arguments: strings.Join(args[1:], " ")}
	for _, rule := range s.persona.Shell.Commands {
		if matchRule(rule, r.Command, args[1:]) {
			r.Output, r.ExitStatus, r.Observation = crlf(rule.Output), rule.ExitStatus, rule.Observation
			r.Delay = time.Duration(rule.DelayMS) * time.Millisecond
			for name, body := range rule.SetFiles {
				value := body
				s.overlay[path.Clean(name)] = &value
			}
			for _, name := range rule.RemoveFiles {
				s.overlay[path.Clean(name)] = nil
			}
			return r
		}
	}
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
			up = time.Duration(30+int(s.seed%30)) * 24 * time.Hour
		}
		r.Output = fmt.Sprintf(" %s up %d days, %02d:%02d,  1 user,  load average: 0.%02d, 0.04, 0.01\r\n", s.now().Format("15:04:05"), int(up.Hours()/24), int(up.Hours())%24, int(up.Minutes())%60, 3+s.seed%8)
	case "date":
		r.Output = s.now().Format("Mon Jan 2 15:04:05 MST 2006") + "\r\n"
	case "cd":
		target := s.user.Home
		if len(args) > 1 {
			target = s.resolve(args[1])
		}
		if s.isDir(target) {
			s.cwd, s.env["PWD"] = target, target
		} else {
			r.Output = "-bash: cd: " + safeArg(args, 1) + ": No such file or directory\r\n"
			r.ExitStatus = 1
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
			r.ExitStatus = 2
		} else {
			r.Output = strings.Join(names, "  ") + "\r\n"
		}
	case "cat", "head", "tail":
		r = s.readCommand(r, args, stdin)
	case "touch":
		for _, name := range nonOptions(args[1:]) {
			value := ""
			s.overlay[s.resolve(name)] = &value
		}
	case "mkdir":
		for _, name := range nonOptions(args[1:]) {
			value := ""
			s.overlay[path.Clean(s.resolve(name))+"/"] = &value
		}
	case "rm":
		for _, name := range nonOptions(args[1:]) {
			s.overlay[s.resolve(name)] = nil
		}
	case "echo":
		r.Output = strings.Join(args[1:], " ") + "\r\n"
	case "printf":
		if len(args) > 1 {
			r.Output = crlf(strings.ReplaceAll(args[1], "\\n", "\n"))
			if len(args) > 2 {
				r.Output = strings.ReplaceAll(r.Output, "%s", strings.Join(args[2:], " "))
			}
		}
	case "env":
		for _, k := range sortedKeys(s.env) {
			r.Output += k + "=" + s.env[k] + "\r\n"
		}
	case "export":
		for _, item := range args[1:] {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) == 2 && validEnv(parts[0]) {
				s.env[parts[0]] = parts[1]
			}
		}
	case "unset":
		for _, k := range args[1:] {
			delete(s.env, k)
		}
	case "which", "command":
		if len(args) > 1 && knownCommand(path.Base(args[len(args)-1])) {
			r.Output = "/usr/bin/" + path.Base(args[len(args)-1]) + "\r\n"
		} else {
			r.ExitStatus = 1
		}
	case "ps":
		r.Output = s.processes()
	case "systemctl", "service":
		r.Output, r.ExitStatus = s.services(args)
	case "dpkg", "apt", "apt-get":
		r.Output, r.ExitStatus = s.packages(r.Command, args)
	case "ip", "ifconfig":
		r.Output = s.interfaces()
	case "ss", "netstat":
		r.Output = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\r\ntcp   LISTEN 0      128    0.0.0.0:22       0.0.0.0:*\r\n"
	case "df":
		r.Output = "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n/dev/vda1       20511312 4829120  14617344  25% /\r\n"
	case "free":
		r.Output = "               total        used        free      shared  buff/cache   available\r\nMem:         2027856      382144      940120       18844      705592     1485712\r\nSwap:              0           0           0\r\n"
	case "grep":
		r = grepCommand(r, args, stdin)
	case "wc":
		r.Output = fmt.Sprintf("%d %d %d\r\n", strings.Count(stdin, "\n"), len(strings.Fields(stdin)), len(stdin))
	case "find":
		root := s.cwd
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			root = s.resolve(args[1])
		}
		for _, p := range s.paths() {
			if strings.HasPrefix(p, root) {
				r.Output += p + "\r\n"
			}
		}
	case "curl", "wget":
		r = s.network(r, args)
	case "chmod", "crontab":
	case "sudo":
		r.Output = "[sudo] password for " + s.user.Name + ": \r\nsudo: a password is required\r\n"
		r.ExitStatus = 1
	case "bash", "sh", "dash", "python", "python3", "perl", "ruby", "node":
		r.Output = r.Command + ": interactive execution unavailable\r\n"
		r.Unsupported = true
		r.ExitStatus = 126
		r.Gap = "interpreter invocation"
	case "help":
		r.Output = "GNU bash, version 5.2.15(1)-release. Type `help name' for more information.\r\n"
	default:
		r.Output = r.Command + ": command not found\r\n"
		r.ExitStatus = 127
		r.Unsupported = true
		r.Gap = "unknown command: " + r.Command
	}
	return r
}

func matchRule(rule persona.CommandRule, command string, args []string) bool {
	if rule.Command != command {
		return false
	}
	if len(rule.ArgsExact) > 0 && strings.Join(rule.ArgsExact, "\x00") != strings.Join(args, "\x00") {
		return false
	}
	if len(rule.ArgsPrefix) > len(args) {
		return false
	}
	for i, v := range rule.ArgsPrefix {
		if args[i] != v {
			return false
		}
	}
	joined := strings.Join(args, " ")
	for _, v := range rule.ArgsContains {
		if !strings.Contains(joined, v) {
			return false
		}
	}
	return true
}

func (s *Shell) network(r Result, args []string) Result {
	url := ""
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
			url = a
			r.URLs = append(r.URLs, a)
		}
	}
	for _, rule := range s.persona.Shell.Network {
		if !strings.HasPrefix(url, rule.URLPrefix) {
			continue
		}
		r.ExitStatus = rule.ExitStatus
		if rule.Outcome == "failure" && r.ExitStatus == 0 {
			r.ExitStatus = 6
		}
		if rule.Outcome == "success" {
			r.Output = crlf(rule.Body)
			filename := rule.Filename
			if filename == "" && r.Command == "wget" {
				filename = path.Base(url)
			}
			if filename != "" {
				body := rule.Body
				s.overlay[s.resolve(filename)] = &body
				r.Output = "--2026-01-01--  " + url + "\r\nSaving to: '" + filename + "'\r\n"
			}
		} else {
			r.Output = r.Command + ": unable to resolve host address\r\n"
		}
		return r
	}
	r.Output, r.ExitStatus = r.Command+": unable to resolve host address\r\n", 6
	return r
}

func (s *Shell) readCommand(r Result, args []string, stdin string) Result {
	names := nonOptions(args[1:])
	if len(names) == 0 {
		r.Output = crlf(stdin)
		return r
	}
	for _, name := range names {
		if body, ok := s.read(s.resolve(name)); ok {
			r.Output += crlf(body)
			if !strings.HasSuffix(r.Output, "\r\n") {
				r.Output += "\r\n"
			}
		} else {
			r.Output += r.Command + ": " + name + ": No such file or directory\r\n"
			r.ExitStatus = 1
		}
	}
	return r
}

func grepCommand(r Result, args []string, stdin string) Result {
	pattern := ""
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			pattern = a
			break
		}
	}
	for _, line := range strings.Split(stdin, "\n") {
		if pattern != "" && strings.Contains(line, pattern) {
			r.Output += line + "\r\n"
		}
	}
	if r.Output == "" {
		r.ExitStatus = 1
	}
	return r
}

func (s *Shell) processes() string {
	if len(s.persona.Shell.Processes) == 0 {
		return "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 systemd\r\n  412 ?        00:00:00 sshd\r\n 1337 pts/0    00:00:00 bash\r\n"
	}
	out := "  PID USER     CMD\r\n"
	for _, p := range s.persona.Shell.Processes {
		out += fmt.Sprintf("%5s %-8s %s\r\n", p.PID, p.User, p.Command)
	}
	return out
}

func (s *Shell) services(args []string) (string, int) {
	if len(s.persona.Shell.Services) == 0 {
		return "Unit ssh.service could not be found.\r\n", 4
	}
	name := ""
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") && a != "status" && a != "list-units" {
			name = strings.TrimSuffix(a, ".service")
		}
	}
	out := ""
	for _, v := range s.persona.Shell.Services {
		if name == "" || name == v.Name {
			out += fmt.Sprintf("● %s.service - %s\r\n   Active: %s\r\n", v.Name, v.Description, v.State)
		}
	}
	if out == "" {
		return "Unit " + name + ".service could not be found.\r\n", 4
	}
	return out, 0
}

func (s *Shell) packages(command string, args []string) (string, int) {
	if command != "dpkg" && len(args) > 1 && (args[1] == "install" || args[1] == "remove" || args[1] == "update" || args[1] == "upgrade") {
		return "E: Could not open lock file /var/lib/dpkg/lock-frontend - Permission denied\r\n", 100
	}
	out := ""
	for _, p := range s.persona.Shell.Packages {
		out += fmt.Sprintf("ii  %-24s %s\r\n", p.Name, p.Version)
	}
	return out, 0
}

func (s *Shell) interfaces() string {
	if len(s.persona.Shell.Interfaces) == 0 {
		return "1: lo: <LOOPBACK,UP> mtu 65536 state UNKNOWN\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP\r\n    inet 10.0.0.12/24 scope global eth0\r\n"
	}
	out := ""
	for i, v := range s.persona.Shell.Interfaces {
		out += fmt.Sprintf("%d: %s: <%s> state %s\r\n    inet %s scope global %s\r\n", i+1, v.Name, strings.ToUpper(v.State), strings.ToUpper(v.State), v.Address, v.Name)
	}
	return out
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
func (s *Shell) paths() []string {
	out := s.persona.Paths()
	for p, v := range s.overlay {
		if v != nil {
			out = append(out, p)
		}
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
func nonOptions(v []string) []string {
	out := []string{}
	for _, x := range v {
		if !strings.HasPrefix(x, "-") {
			out = append(out, x)
		}
	}
	return out
}
func safeArg(v []string, i int) string {
	if i >= 0 && i < len(v) {
		q := strconv.QuoteToASCII(v[i])
		return q[1 : len(q)-1]
	}
	return ""
}
func crlf(v string) string {
	v = strings.ReplaceAll(v, "\r\n", "\n")
	return strings.ReplaceAll(v, "\n", "\r\n")
}
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func knownCommand(v string) bool {
	switch v {
	case "cat", "cd", "curl", "date", "df", "echo", "env", "find", "free", "grep", "head", "hostname", "id", "ip", "ls", "mkdir", "ps", "pwd", "rm", "ss", "systemctl", "tail", "touch", "uname", "uptime", "wc", "wget", "whoami":
		return true
	}
	return false
}
