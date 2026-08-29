package persona

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = 1

type Persona struct {
	Version          int             `yaml:"version" json:"version"`
	ID               string          `yaml:"id" json:"id"`
	Host             Host            `yaml:"host" json:"host"`
	Users            []User          `yaml:"users" json:"users"`
	Files            map[string]File `yaml:"files" json:"files"`
	HTTP             HTTP            `yaml:"http" json:"http"`
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
	Path        string   `yaml:"path" json:"path"`
	Methods     []string `yaml:"methods" json:"methods"`
	Status      int      `yaml:"status" json:"status"`
	ContentType string   `yaml:"content_type" json:"content_type"`
	Body        string   `yaml:"body" json:"body"`
	Upload      bool     `yaml:"upload" json:"upload"`
}

func Load(file string) (Persona, error) {
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
	if p.Version != Version {
		return fmt.Errorf("persona version must be %d", Version)
	}
	if p.ID == "" || p.Host.Hostname == "" || p.Host.OS == "" {
		return fmt.Errorf("persona id and host identity are required")
	}
	seen := map[string]bool{}
	for name, f := range p.Files {
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
		if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "..") {
			return fmt.Errorf("unsafe route %q", r.Path)
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
	}
	return nil
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
