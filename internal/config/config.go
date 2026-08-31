package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir        string            `yaml:"data_dir"`
	PersonaFile    string            `yaml:"persona_file"`
	Controller     Controller        `yaml:"controller"`
	Sensors        map[string]Sensor `yaml:"sensors"`
	Limits         Limits            `yaml:"limits"`
	Retention      Retention         `yaml:"retention"`
	Access         Access            `yaml:"access"`
	Alerts         Alerts            `yaml:"alerts"`
	ArtifactWorker ArtifactWorker    `yaml:"artifact_worker,omitempty"`
}
type Controller struct {
	GRPC     string `yaml:"grpc"`
	HTTP     string `yaml:"http"`
	Metrics  string `yaml:"metrics"`
	Identity string `yaml:"identity"`
	TLS      TLS    `yaml:"tls"`
}
type Sensor struct {
	Protocol   string `yaml:"protocol"`
	Listen     string `yaml:"listen"`
	Controller string `yaml:"controller"`
	TLS        TLS    `yaml:"tls"`
}
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}
type Limits struct {
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	SessionCap        time.Duration `yaml:"session_cap"`
	TranscriptBytes   int64         `yaml:"transcript_bytes"`
	RequestBytes      int64         `yaml:"request_bytes"`
	ArtifactBytes     int64         `yaml:"artifact_bytes"`
	GlobalSessions    int           `yaml:"global_sessions"`
	PerSourceSessions int           `yaml:"per_source_sessions"`
	SpoolBytes        int64         `yaml:"spool_bytes"`
}
type Retention struct {
	MetadataDays   int   `yaml:"metadata_days" json:"metadata_days"`
	TranscriptDays int   `yaml:"transcript_days" json:"transcript_days"`
	PCAPDays       int   `yaml:"pcap_days,omitempty" json:"-"`
	PayloadDays    int   `yaml:"payload_days" json:"payload_days"`
	TotalBytes     int64 `yaml:"total_bytes" json:"total_bytes"`
}
type Access struct {
	BearerToken    string   `yaml:"bearer_token"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}
type Alerts struct {
	Webhooks             []string             `yaml:"webhooks" json:"webhooks"`
	SourceSpikePerMinute int                  `yaml:"source_spike_per_minute" json:"source_spike_per_minute"`
	WebhookSigningSecret string               `yaml:"webhook_signing_secret,omitempty" json:"webhook_signing_secret,omitempty"`
	Rules                map[string]AlertRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}
type AlertRule struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Severity        string `yaml:"severity,omitempty" json:"severity,omitempty"`
	CooldownMinutes int    `yaml:"cooldown_minutes,omitempty" json:"cooldown_minutes,omitempty"`
}
type ArtifactWorker struct {
	URL   string `yaml:"url" json:"url,omitempty"`
	Token string `yaml:"token" json:"-"`
}

func Defaults() Config {
	return Config{
		DataDir: "./data", PersonaFile: "./personas/default.yaml",
		Controller: Controller{GRPC: "0.0.0.0:9443", HTTP: "127.0.0.1:9080", Metrics: "127.0.0.1:9090"},
		Limits:     Limits{IdleTimeout: 10 * time.Minute, SessionCap: 2 * time.Hour, TranscriptBytes: 5 << 20, RequestBytes: 10 << 20, ArtifactBytes: 50 << 20, GlobalSessions: 500, PerSourceSessions: 20, SpoolBytes: 512 << 20},
		Retention:  Retention{MetadataDays: 180, TranscriptDays: 90, PCAPDays: 14, PayloadDays: 30, TotalBytes: 20 << 30},
		Alerts:     Alerts{SourceSpikePerMinute: 60}, Sensors: map[string]Sensor{},
	}
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c := Defaults()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err = dec.Decode(&c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if err = dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not supported")
		}
		return c, fmt.Errorf("parse config: %w", err)
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.DataDir = resolve(c.DataDir)
	c.PersonaFile = resolve(c.PersonaFile)
	c.Controller.TLS.Cert = resolve(c.Controller.TLS.Cert)
	c.Controller.TLS.Key = resolve(c.Controller.TLS.Key)
	c.Controller.TLS.CA = resolve(c.Controller.TLS.CA)
	c.Controller.Identity = resolve(c.Controller.Identity)
	for id, s := range c.Sensors {
		s.TLS.Cert = resolve(s.TLS.Cert)
		s.TLS.Key = resolve(s.TLS.Key)
		s.TLS.CA = resolve(s.TLS.CA)
		c.Sensors[id] = s
	}
	if v := os.Getenv("FYKE_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("FYKE_CONTROLLER_IDENTITY"); v != "" {
		c.Controller.Identity = v
	}
	if v := os.Getenv("FYKE_CONTROLLER_HTTP"); v != "" {
		c.Controller.HTTP = v
	}
	if v := os.Getenv("FYKE_ARTIFACT_WORKER_URL"); v != "" {
		c.ArtifactWorker.URL = v
	}
	if v := os.Getenv("FYKE_ARTIFACT_WORKER_TOKEN"); v != "" {
		c.ArtifactWorker.Token = v
	}
	if v := os.Getenv("FYKE_GLOBAL_SESSIONS"); v != "" {
		n, parseErr := strconv.Atoi(v)
		if parseErr != nil {
			return c, fmt.Errorf("FYKE_GLOBAL_SESSIONS must be numeric")
		}
		c.Limits.GlobalSessions = n
	}
	if v := os.Getenv("FYKE_PER_SOURCE_SESSIONS"); v != "" {
		n, parseErr := strconv.Atoi(v)
		if parseErr != nil {
			return c, fmt.Errorf("FYKE_PER_SOURCE_SESSIONS must be numeric")
		}
		c.Limits.PerSourceSessions = n
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.DataDir == "" || c.PersonaFile == "" {
		return fmt.Errorf("data_dir and persona_file are required")
	}
	if c.Controller.Identity == "" || c.Controller.TLS.Cert == "" || c.Controller.TLS.Key == "" || c.Controller.TLS.CA == "" {
		return fmt.Errorf("controller identity and TLS files are required")
	}
	if _, e := validTCPAddress("controller.grpc", c.Controller.GRPC); e != nil {
		return e
	}
	httpHost, e := validTCPAddress("controller.http", c.Controller.HTTP)
	if e != nil {
		return e
	}
	if httpHost != "127.0.0.1" && httpHost != "::1" && !(os.Getenv("FYKE_CONTAINER") == "1" && httpHost == "0.0.0.0") {
		return fmt.Errorf("controller.http must bind loopback (container exception requires FYKE_CONTAINER=1 and host loopback publishing)")
	}
	metricsHost, e := validTCPAddress("controller.metrics", c.Controller.Metrics)
	if e != nil {
		return e
	}
	if metricsHost != "127.0.0.1" && metricsHost != "::1" {
		return fmt.Errorf("controller.metrics must bind loopback")
	}
	if c.Limits.IdleTimeout <= 0 || c.Limits.SessionCap <= 0 || c.Limits.TranscriptBytes < 1024 || c.Limits.RequestBytes < 1024 || c.Limits.ArtifactBytes < 1024 || c.Limits.SpoolBytes < 1<<20 {
		return fmt.Errorf("invalid limits")
	}
	if c.Limits.GlobalSessions < 1 || c.Limits.PerSourceSessions < 1 || c.Limits.PerSourceSessions > c.Limits.GlobalSessions {
		return fmt.Errorf("invalid session concurrency")
	}
	if c.Retention.MetadataDays < 1 || c.Retention.TranscriptDays < 1 || c.Retention.PCAPDays < 1 || c.Retention.PayloadDays < 1 || c.Retention.TotalBytes < 1<<20 {
		return fmt.Errorf("invalid retention")
	}
	for id, s := range c.Sensors {
		if id == "" || s.Listen == "" || s.Controller == "" || s.TLS.Cert == "" || s.TLS.Key == "" || s.TLS.CA == "" {
			return fmt.Errorf("sensor %q incomplete", id)
		}
		if _, e = validTCPAddress("sensor "+id+" listen", s.Listen); e != nil {
			return e
		}
		if _, e = validTCPAddress("sensor "+id+" controller", s.Controller); e != nil {
			return e
		}
		switch s.Protocol {
		case "ssh", "telnet", "http", "https":
		default:
			return fmt.Errorf("sensor %q has unsupported protocol %q", id, s.Protocol)
		}
	}
	if c.ArtifactWorker.URL != "" {
		u, parseErr := url.Parse(c.ArtifactWorker.URL)
		if parseErr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("artifact_worker.url must be an absolute HTTP or HTTPS URL")
		}
		if len(c.ArtifactWorker.Token) < 32 {
			return fmt.Errorf("artifact_worker.token must contain at least 32 characters")
		}
	}
	return c.Alerts.Validate()
}

func validTCPAddress(name, address string) (string, error) {
	host, rawPort, e := net.SplitHostPort(address)
	if e != nil || host == "" {
		return "", fmt.Errorf("%s must be a host:port address", name)
	}
	port, e := strconv.Atoi(rawPort)
	if e != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%s has an invalid TCP port", name)
	}
	return host, nil
}

func (a Alerts) Validate() error {
	if a.SourceSpikePerMinute < 0 {
		return fmt.Errorf("source_spike_per_minute cannot be negative")
	}
	for _, raw := range a.Webhooks {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("alert webhook must use an absolute https URL")
		}
	}
	if a.WebhookSigningSecret != "" && len(a.WebhookSigningSecret) < 32 {
		return fmt.Errorf("webhook_signing_secret must contain at least 32 characters")
	}
	for name, rule := range a.Rules {
		if name == "" || rule.CooldownMinutes < 0 {
			return fmt.Errorf("invalid alert rule %q", name)
		}
		switch rule.Severity {
		case "", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("alert rule %q has invalid severity", name)
		}
	}
	return nil
}
