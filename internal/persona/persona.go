package persona

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const Version = 2

type Persona struct {
	Version          int             `yaml:"version" json:"version"`
	ID               string          `yaml:"id" json:"id"`
	Host             Host            `yaml:"host" json:"host"`
	Users            []User          `yaml:"users" json:"users"`
	Files            map[string]File `yaml:"files" json:"files"`
	HTTP             HTTP            `yaml:"http" json:"http"`
	Shell            Shell           `yaml:"shell,omitempty" json:"shell,omitempty"`
	HoneyCredentials []Credential    `yaml:"honey_credentials" json:"-"`
}
type Host struct {
	Hostname     string    `yaml:"hostname" json:"hostname"`
	OS           string    `yaml:"os" json:"os"`
	Kernel       string    `yaml:"kernel" json:"kernel"`
	SSHBanner    string    `yaml:"ssh_banner" json:"ssh_banner"`
	TelnetBanner string    `yaml:"telnet_banner" json:"telnet_banner"`
	BootedAt     time.Time `yaml:"booted_at" json:"booted_at"`
}
type User struct {
	Name  string `yaml:"name" json:"name"`
	UID   int    `yaml:"uid" json:"uid"`
	Home  string `yaml:"home" json:"home"`
	Shell string `yaml:"shell" json:"shell"`
}
type File struct {
	Content string `yaml:"content" json:"content"`
	Mode    uint32 `yaml:"mode" json:"mode"`
}
type Credential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
type HTTP struct {
	Server string  `yaml:"server" json:"server"`
	Routes []Route `yaml:"routes" json:"routes"`
}
type Route struct {
	Path         string            `yaml:"path" json:"path"`
	PathPattern  string            `yaml:"path_pattern,omitempty" json:"path_pattern,omitempty"`
	Methods      []string          `yaml:"methods" json:"methods"`
	Status       int               `yaml:"status" json:"status"`
	ContentType  string            `yaml:"content_type" json:"content_type"`
	Body         string            `yaml:"body" json:"body"`
	Upload       bool              `yaml:"upload" json:"upload"`
	Query        map[string]string `yaml:"query,omitempty" json:"query,omitempty"`
	Headers      map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	RequireState map[string]string `yaml:"require_state,omitempty" json:"require_state,omitempty"`
	SetState     map[string]string `yaml:"set_state,omitempty" json:"set_state,omitempty"`
	DelayMS      int               `yaml:"delay_ms,omitempty" json:"delay_ms,omitempty"`
}
type Shell struct {
	Environment map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Processes   []Process         `yaml:"processes,omitempty" json:"processes,omitempty"`
	Services    []Service         `yaml:"services,omitempty" json:"services,omitempty"`
	Packages    []Package         `yaml:"packages,omitempty" json:"packages,omitempty"`
	Interfaces  []Interface       `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
	Commands    []CommandRule     `yaml:"commands,omitempty" json:"commands,omitempty"`
	Network     []NetworkRule     `yaml:"network,omitempty" json:"network,omitempty"`
}
type Process struct {
	PID     string `yaml:"pid" json:"pid"`
	User    string `yaml:"user" json:"user"`
	Command string `yaml:"command" json:"command"`
}
type Service struct {
	Name        string `yaml:"name" json:"name"`
	State       string `yaml:"state" json:"state"`
	Description string `yaml:"description" json:"description"`
}
type Package struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
}
type Interface struct {
	Name    string `yaml:"name" json:"name"`
	Address string `yaml:"address" json:"address"`
	State   string `yaml:"state" json:"state"`
}
type CommandRule struct {
	Command      string            `yaml:"command" json:"command"`
	ArgsExact    []string          `yaml:"args_exact,omitempty" json:"args_exact,omitempty"`
	ArgsPrefix   []string          `yaml:"args_prefix,omitempty" json:"args_prefix,omitempty"`
	ArgsContains []string          `yaml:"args_contains,omitempty" json:"args_contains,omitempty"`
	Output       string            `yaml:"output,omitempty" json:"output,omitempty"`
	ExitStatus   int               `yaml:"exit_status,omitempty" json:"exit_status,omitempty"`
	DelayMS      int               `yaml:"delay_ms,omitempty" json:"delay_ms,omitempty"`
	SetFiles     map[string]string `yaml:"set_files,omitempty" json:"set_files,omitempty"`
	RemoveFiles  []string          `yaml:"remove_files,omitempty" json:"remove_files,omitempty"`
	Observation  string            `yaml:"observation,omitempty" json:"observation,omitempty"`
}
type NetworkRule struct {
	URLPrefix  string `yaml:"url_prefix" json:"url_prefix"`
	Outcome    string `yaml:"outcome" json:"outcome"`
	Body       string `yaml:"body,omitempty" json:"body,omitempty"`
	Filename   string `yaml:"filename,omitempty" json:"filename,omitempty"`
	ExitStatus int    `yaml:"exit_status,omitempty" json:"exit_status,omitempty"`
}

func Load(file string) (Persona, error) {
	info, e := os.Stat(file)
	if e != nil {
		return Persona{}, e
	}
	if info.Size() > 4<<20 {
		return Persona{}, fmt.Errorf("persona file exceeds 4 MiB")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		return Persona{}, e
	}
	var p Persona
	if e = yaml.Unmarshal(b, &p); e != nil {
		return p, e
	}
	return p, p.Validate()
}
func (p Persona) Validate() error {
	if p.Version != 1 && p.Version != Version {
		return fmt.Errorf("persona version must be 1 or %d", Version)
	}
	if p.ID == "" || p.Host.Hostname == "" || p.Host.OS == "" {
		return fmt.Errorf("persona id and host identity are required")
	}
	if !safeHeaderValue(p.HTTP.Server) || !safeHeaderValue(p.Host.SSHBanner) || strings.ContainsAny(p.Host.Hostname, "\r\n\x00") {
		return fmt.Errorf("persona contains an unsafe banner or server value")
	}
	if len(p.Users) > 128 || len(p.Files) > 10000 || len(p.HTTP.Routes) > 1000 || len(p.Shell.Commands) > 1000 || len(p.Shell.Network) > 1000 {
		return fmt.Errorf("persona exceeds collection limits")
	}
	seen := map[string]bool{}
	for name, f := range p.Files {
		if len(f.Content) > 1<<20 {
			return fmt.Errorf("persona file %q exceeds 1 MiB", name)
		}
		clean := path.Clean("/" + name)
		if clean != name || strings.ContainsRune(name, '\x00') {
			return fmt.Errorf("unsafe persona path %q", name)
		}
		if f.Mode&0111 != 0 {
			return fmt.Errorf("executable persona file %q is forbidden", name)
		}
		seen[name] = true
	}
	for _, u := range p.Users {
		if u.Name == "" || u.Home == "" || !strings.HasPrefix(path.Clean(u.Home), "/") {
			return fmt.Errorf("invalid user")
		}
	}
	for _, r := range p.HTTP.Routes {
		if !safeHeaderValue(r.ContentType) {
			return fmt.Errorf("route contains an unsafe content type")
		}
		if len(r.Body) > 1<<20 || len(r.Query) > 100 || len(r.Headers) > 100 || len(r.RequireState) > 100 || len(r.SetState) > 100 {
			return fmt.Errorf("route exceeds content or state limits")
		}
		pattern := r.Path
		if r.PathPattern != "" {
			pattern = r.PathPattern
		}
		if !strings.HasPrefix(pattern, "/") || strings.Contains(pattern, "..") {
			return fmt.Errorf("unsafe route %q", pattern)
		}
		if r.Status < 100 || r.Status > 599 {
			return fmt.Errorf("invalid route status")
		}
		for _, m := range r.Methods {
			switch strings.ToUpper(m) {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			default:
				return fmt.Errorf("unsupported method %q", m)
			}
		}
		if r.DelayMS < 0 || r.DelayMS > 30000 {
			return fmt.Errorf("route delay must be between 0 and 30000 ms")
		}
		for k, v := range r.SetState {
			if !stateKey(k) || len(v) > 512 {
				return fmt.Errorf("invalid route state")
			}
		}
		for k, v := range r.RequireState {
			if !stateKey(k) || len(v) > 512 {
				return fmt.Errorf("invalid required route state")
			}
		}
	}
	for _, rule := range p.Shell.Commands {
		if rule.Command == "" || strings.ContainsAny(rule.Command, "/\\ \t\r\n") {
			return fmt.Errorf("invalid command rule")
		}
		if rule.ExitStatus < 0 || rule.ExitStatus > 255 || rule.DelayMS < 0 || rule.DelayMS > 30000 || len(rule.Output) > 1<<20 {
			return fmt.Errorf("invalid command rule limits")
		}
		for name := range rule.SetFiles {
			clean := path.Clean("/" + name)
			if clean != name {
				return fmt.Errorf("unsafe command file path %q", name)
			}
		}
	}
	for _, rule := range p.Shell.Network {
		if len(rule.Body) > 1<<20 || len(rule.URLPrefix) > 4096 {
			return fmt.Errorf("network rule exceeds content limits")
		}
		if !strings.HasPrefix(rule.URLPrefix, "http://") && !strings.HasPrefix(rule.URLPrefix, "https://") {
			return fmt.Errorf("network rule must use an HTTP URL prefix")
		}
		if rule.Outcome != "success" && rule.Outcome != "failure" {
			return fmt.Errorf("network rule outcome must be success or failure")
		}
	}
	return nil
}

func stateKey(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if c != '_' && c != '-' && c != '.' && !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}
func safeHeaderValue(value string) bool {
	return len(value) <= 1024 && !strings.ContainsAny(value, "\r\n\x00")
}
func (p Persona) User(name string) (User, bool) {
	for _, u := range p.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}
func (p Persona) PasswordAccepted(user, pass string) bool {
	for _, c := range p.HoneyCredentials {
		if c.Username == user && c.Password == pass {
			return true
		}
	}
	return false
}
func (p Persona) Paths() []string {
	v := make([]string, 0, len(p.Files))
	for n := range p.Files {
		v = append(v, n)
	}
	sort.Strings(v)
	return v
}
