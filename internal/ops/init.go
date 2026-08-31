package ops

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/cryptokit"
)

func Init(dir string) error {
	if dir == "" {
		return fmt.Errorf("directory required")
	}
	if entries, e := os.ReadDir(dir); e == nil && len(entries) > 0 {
		return fmt.Errorf("refusing to initialize non-empty directory %s", dir)
	}
	for _, d := range []string{"pki", "personas", "data", "spool"} {
		if e := os.MkdirAll(filepath.Join(dir, d), 0700); e != nil {
			return e
		}
	}
	ca, caPEM, e := newCA()
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "pki", "ca.crt"), caPEM, 0644); e != nil {
		return e
	}
	if e = ca.issue(filepath.Join(dir, "pki"), "controller", []string{"controller", "localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, false); e != nil {
		return e
	}
	for _, id := range []string{"ssh", "telnet", "http", "https"} {
		if e = ca.issue(filepath.Join(dir, "pki"), "sensor-"+id, []string{"sensor." + id}, nil, true); e != nil {
			return e
		}
	}
	if e = EnsurePublicHTTPSCertificate(filepath.Join(dir, "pki"), "edge-gw-01"); e != nil {
		return e
	}
	if _, e = cryptokit.GenerateIdentity(filepath.Join(dir, "controller.agekey")); e != nil {
		return e
	}
	if e = hostKey(filepath.Join(dir, "pki", "ssh_host_ed25519_key")); e != nil {
		return e
	}
	personaYAML := strings.Replace(defaultPersona, "{{BOOTED_AT}}", time.Now().Add(-37*time.Hour).UTC().Format(time.RFC3339), 1)
	if e = os.WriteFile(filepath.Join(dir, "personas", "default.yaml"), []byte(personaYAML), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(defaultConfig), 0600); e != nil {
		return e
	}
	return nil
}
func hostKey(file string) error {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	return os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
}

const defaultPersona = `version: 1
id: debian-edge-01
host:
  hostname: edge-gw-01
  os: Debian GNU/Linux 12 (bookworm)
  kernel: 6.1.0-18-amd64
  ssh_banner: OpenSSH_9.2p1 Debian-2+deb12u5
  telnet_banner: Debian GNU/Linux 12 edge-gw-01 ttyS0
  booted_at: {{BOOTED_AT}}
users:
  - {name: root, uid: 0, home: /root, shell: /bin/bash}
  - {name: deploy, uid: 1001, home: /home/deploy, shell: /bin/bash}
honey_credentials:
  - {username: deploy, password: deploy123}
files:
  /etc/hostname: {mode: 420, content: "edge-gw-01\n"}
  /etc/os-release: {mode: 420, content: "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"}
  /etc/passwd: {mode: 420, content: "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n"}
  /home/deploy/README.txt: {mode: 420, content: "Edge deployment staging host.\n"}
http:
  server: nginx/1.22.1
  routes:
    - {path: /, methods: [GET, HEAD], status: 200, content_type: "text/html; charset=utf-8", body: "<!doctype html><title>Edge Gateway</title><h1>Gateway Console</h1>"}
    - {path: /login, methods: [GET, POST], status: 200, content_type: "text/html; charset=utf-8", body: "<!doctype html><title>Sign in</title><form method=post><input name=username><input name=password type=password></form>"}
    - {path: /api/upload, methods: [POST, PUT], status: 201, content_type: application/json, body: "{\"status\":\"queued\"}", upload: true}
`
const defaultConfig = `data_dir: ./data
persona_file: ./personas/default.yaml
controller:
  grpc: 0.0.0.0:9443
  http: 127.0.0.1:9080
  metrics: 127.0.0.1:9090
  identity: ./controller.agekey
  tls: {cert: ./pki/controller.crt, key: ./pki/controller.key, ca: ./pki/ca.crt}
sensors:
  ssh: {protocol: ssh, listen: "0.0.0.0:2222", controller: "controller:9443", tls: {cert: ./pki/sensor-ssh.crt, key: ./pki/sensor-ssh.key, ca: ./pki/ca.crt}}
  telnet: {protocol: telnet, listen: "0.0.0.0:2323", controller: "controller:9443", tls: {cert: ./pki/sensor-telnet.crt, key: ./pki/sensor-telnet.key, ca: ./pki/ca.crt}}
  http: {protocol: http, listen: "0.0.0.0:8080", controller: "controller:9443", tls: {cert: ./pki/sensor-http.crt, key: ./pki/sensor-http.key, ca: ./pki/ca.crt}}
  https: {protocol: https, listen: "0.0.0.0:8443", controller: "controller:9443", tls: {cert: ./pki/sensor-https.crt, key: ./pki/sensor-https.key, ca: ./pki/ca.crt}}
limits: {idle_timeout: 10m, session_cap: 2h, transcript_bytes: 5242880, request_bytes: 10485760, artifact_bytes: 52428800, global_sessions: 500, per_source_sessions: 20, spool_bytes: 536870912}
retention: {metadata_days: 180, transcript_days: 90, pcap_days: 14, payload_days: 30, total_bytes: 21474836480}
access: {bearer_token: "", trusted_proxies: [127.0.0.1, "::1"]}
alerts: {webhooks: [], source_spike_per_minute: 60}
`
