package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/controller"
	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/ops"
	"github.com/ksahoo/fyke/internal/persona"
	"github.com/ksahoo/fyke/internal/protocol/httpdecoy"
	"github.com/ksahoo/fyke/internal/protocol/sshdecoy"
	"github.com/ksahoo/fyke/internal/protocol/telnet"
	"github.com/ksahoo/fyke/internal/sensor"
	"github.com/ksahoo/fyke/internal/spool"
	"github.com/ksahoo/fyke/internal/store"
	"github.com/ksahoo/fyke/internal/transport"
	"github.com/ksahoo/fyke/internal/web"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(os.Args[1:]); e != nil {
		slog.Error("fyke stopped", "error", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "init":
		return initCmd(args[1:])
	case "controller":
		return controllerCmd(args[1:])
	case "sensor":
		return sensorCmd(args[1:])
	case "doctor":
		return doctorCmd(args[1:])
	case "firewall":
		return firewallCmd(args[1:])
	case "backup":
		return backupCmd(args[1:])
	case "restore":
		return restoreCmd(args[1:])
	case "export":
		return exportCmd(args[1:])
	case "volume-init":
		return ops.InitVolumes(args[1:])
	default:
		return usage()
	}
}
func usage() error {
	fmt.Fprintln(os.Stderr, "usage: fyke <controller|sensor|init|doctor|firewall|backup|restore|export|version>")
	return errors.New("command required")
}
func initCmd(args []string) error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := f.String("dir", "./fyke-data", "initialization directory")
	if e := f.Parse(args); e != nil {
		return e
	}
	if e := ops.Init(*dir); e != nil {
		return e
	}
	fmt.Printf("initialized Fyke in %s\ncontroller age identity is private; back it up securely\n", *dir)
	return nil
}
func load(args []string, name string) (config.Config, error) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	file := f.String("config", "config.yaml", "configuration file")
	if e := f.Parse(args); e != nil {
		return config.Config{}, e
	}
	return config.Load(*file)
}
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
func controllerCmd(args []string) error {
	c, e := load(args, "controller")
	if e != nil {
		return e
	}
	sealer, e := cryptokit.Load(c.Controller.Identity)
	if e != nil {
		return e
	}
	st, e := store.Open(c.DataDir, sealer)
	if e != nil {
		return e
	}
	defer st.Close()
	ctx, cancel := signalContext()
	defer cancel()
	broker := controller.NewBroker()
	api := controller.NewAPI(st, broker, c)
	alerts := controller.NewAlertEngine(ctx, st, broker, c.Alerts)
	publish := func(event model.Event) { broker.Publish(event); alerts.Process(event) }
	errs := make(chan error, 3)
	go func() {
		errs <- transport.ServeGRPC(ctx, c.Controller.GRPC, [3]string{c.Controller.TLS.Cert, c.Controller.TLS.Key, c.Controller.TLS.CA}, transport.NewServer(st, publish))
	}()
	go func() { errs <- controller.ServeHTTP(ctx, c.Controller.HTTP, api.Handler(web.Handler())) }()
	go func() { errs <- controller.ServeMetrics(ctx, c.Controller.Metrics, st) }()
	go retentionLoop(ctx, st, c)
	e = <-errs
	cancel()
	return e
}
func retentionLoop(ctx context.Context, st *store.Store, c config.Config) {
	tick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			p := c.Retention
			if _, e := st.Prune(ctx, store.RetentionPolicy{MetadataDays: p.MetadataDays, TranscriptDays: p.TranscriptDays, PCAPDays: p.PCAPDays, PayloadDays: p.PayloadDays, TotalBytes: p.TotalBytes}); e != nil {
				slog.Error("retention failed", "error", e)
			}
		case <-ctx.Done():
			return
		}
	}
}
func sensorCmd(args []string) error {
	f := flag.NewFlagSet("sensor", flag.ContinueOnError)
	file := f.String("config", "config.yaml", "configuration file")
	id := f.String("id", "", "sensor id")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *id == "" {
		return fmt.Errorf("--id required")
	}
	c, e := config.Load(*file)
	if e != nil {
		return e
	}
	sc, ok := c.Sensors[*id]
	if !ok {
		return fmt.Errorf("sensor %q not configured", *id)
	}
	p, e := persona.Load(c.PersonaFile)
	if e != nil {
		return e
	}
	sp, e := spool.Open(filepath.Join(c.DataDir, "spool", *id), c.Limits.SpoolBytes)
	if e != nil {
		return e
	}
	client, e := transport.NewClient(*id, sc.Controller, sp, sc.TLS.Cert, sc.TLS.Key, sc.TLS.CA)
	if e != nil {
		return e
	}
	ctx, cancel := signalContext()
	defer cancel()
	go client.Run(ctx)
	limit := sensor.NewLimiter(c.Limits.GlobalSessions, c.Limits.PerSourceSessions)
	gate := sensor.NewAuthGate(p)
	switch sc.Protocol {
	case "ssh":
		srv := sshdecoy.Server{ID: *id, Address: sc.Listen, HostKey: filepath.Join(filepath.Dir(sc.TLS.Cert), "ssh_host_ed25519_key"), Persona: p, Sink: client, Gate: gate, Limiter: limit, Idle: c.Limits.IdleTimeout, Cap: c.Limits.SessionCap, Transcript: c.Limits.TranscriptBytes, ArtifactBytes: c.Limits.ArtifactBytes}
		return srv.Serve(ctx)
	case "telnet":
		srv := telnet.Server{ID: *id, Address: sc.Listen, Persona: p, Sink: client, Gate: gate, Limiter: limit, Idle: c.Limits.IdleTimeout, Cap: c.Limits.SessionCap, Transcript: c.Limits.TranscriptBytes}
		return srv.Serve(ctx)
	case "http", "https":
		srv := httpdecoy.Server{ID: *id, Protocol: sc.Protocol, Address: sc.Listen, Persona: p, Sink: client, Limiter: limit, Idle: c.Limits.IdleTimeout, Cap: c.Limits.SessionCap, RequestBytes: c.Limits.RequestBytes, ArtifactBytes: c.Limits.ArtifactBytes, Transcript: c.Limits.TranscriptBytes, TLSCert: sc.TLS.Cert, TLSKey: sc.TLS.Key}
		return srv.Serve(ctx)
	}
	return fmt.Errorf("unsupported protocol")
}
func doctorCmd(args []string) error {
	c, e := load(args, "doctor")
	if e != nil {
		return e
	}
	if _, e = persona.Load(c.PersonaFile); e != nil {
		return fmt.Errorf("persona: %w", e)
	}
	if _, e = os.Stat(c.Controller.Identity); e != nil {
		return fmt.Errorf("controller identity: %w", e)
	}
	fmt.Println("ok: configuration and persona are valid")
	fmt.Println("warning: verify Tailscale Serve or alternate-port administration before publishing ports 22/23/80/443")
	fmt.Println("warning: containment requires `fyke firewall apply`; Compose isolation is not a host firewall")
	if os.Getenv("FYKE_PCAP") != "" {
		fmt.Println("warning: PCAP profile weakens isolation by granting NET_RAW")
	}
	return nil
}
func firewallCmd(args []string) error {
	if len(args) == 0 || args[0] != "apply" {
		fmt.Print(ops.FirewallRules())
		return fmt.Errorf("firewall changes are explicit: run `fyke firewall apply --config config.yaml`")
	}
	c, e := load(args[1:], "firewall apply")
	if e != nil {
		return e
	}
	return ops.FirewallApply(c.DataDir)
}

func backupCmd(args []string) error {
	f := flag.NewFlagSet("backup", flag.ContinueOnError)
	file := f.String("config", "config.yaml", "configuration file")
	recipient := f.String("recipient", "", "age X25519 recovery recipient")
	out := f.String("out", "fyke-backup.tar.age", "output archive")
	if e := f.Parse(args); e != nil {
		return e
	}
	c, e := config.Load(*file)
	if e != nil {
		return e
	}
	return ops.Backup(context.Background(), c, *recipient, *out)
}
func restoreCmd(args []string) error {
	f := flag.NewFlagSet("restore", flag.ContinueOnError)
	backup := f.String("backup", "", "encrypted backup")
	identity := f.String("identity", "", "operator recovery age identity file")
	target := f.String("target", "./restored", "empty restore target")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *backup == "" || *identity == "" {
		return fmt.Errorf("--backup and --identity are required")
	}
	return ops.Restore(*backup, *identity, *target)
}
func exportCmd(args []string) error {
	f := flag.NewFlagSet("export", flag.ContinueOnError)
	file := f.String("config", "config.yaml", "configuration file")
	format := f.String("format", "jsonl", "jsonl or csv")
	out := f.String("out", "", "output file (stdout if empty)")
	sensitive := f.Bool("include-sensitive", false, "audit explicit sensitive export request")
	if e := f.Parse(args); e != nil {
		return e
	}
	c, e := config.Load(*file)
	if e != nil {
		return e
	}
	return ops.Export(context.Background(), c, *format, *out, *sensitive)
}
