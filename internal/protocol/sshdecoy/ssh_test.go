package sshdecoy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/persona"
	"github.com/ksahoo/fyke/internal/sensor"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type collectingSink struct {
	mu     sync.Mutex
	events []model.Event
}

func (s *collectingSink) Emit(_ context.Context, e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func TestSSHSessionStateSFTPAndSCPRejection(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skipf("local sockets unavailable: %v", e)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	hostKey := filepath.Join(t.TempDir(), "host_key")
	if e = os.WriteFile(hostKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	p := persona.Persona{Version: 2, ID: "test", Host: persona.Host{Hostname: "edge", OS: "Debian", Kernel: "6.1", SSHBanner: "OpenSSH_9.2"}, Users: []persona.User{{Name: "deploy", UID: 1001, Home: "/home/deploy", Shell: "/bin/bash"}}, HoneyCredentials: []persona.Credential{{Username: "deploy", Password: "secret"}}, Files: map[string]persona.File{"/home/deploy/readme.txt": {Content: "safe\n", Mode: 0444}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &collectingSink{}
	server := &Server{ID: "ssh", Address: address, HostKey: hostKey, Persona: p, Sink: sink, Gate: sensor.NewAuthGate(p), Limiter: sensor.NewLimiter(10, 10), Idle: time.Minute, Cap: time.Minute, Transcript: 1 << 20, ArtifactBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	config := &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}
	var client *ssh.Client
	for i := 0; i < 50; i++ {
		client, e = ssh.Dial("tcp", address, config)
		if e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	first, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if e = first.Run("touch shared.txt"); e != nil {
		t.Fatal(e)
	}
	second, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	listing, e := second.Output("ls")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(listing), "shared.txt") {
		t.Fatalf("session state not shared: %q", listing)
	}
	sftpClient, e := sftp.NewClient(client)
	if e != nil {
		t.Fatal(e)
	}
	file, e := sftpClient.Open("/home/deploy/readme.txt")
	if e != nil {
		t.Fatal(e)
	}
	body := make([]byte, 16)
	n, e := file.Read(body)
	if e != nil && n == 0 {
		t.Fatal(e)
	}
	_ = file.Close()
	if string(body[:n]) != "safe\n" {
		t.Fatalf("sftp read=%q", body[:n])
	}
	uploaded, e := sftpClient.Create("/tmp/tool.bin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = uploaded.Write([]byte("artifact")); e != nil {
		t.Fatal(e)
	}
	if e = uploaded.Close(); e != nil {
		t.Fatal(e)
	}
	_ = sftpClient.Close()
	sink.mu.Lock()
	sawUpload := false
	for _, event := range sink.events {
		if event.Type == "artifact.upload" {
			sawUpload = true
		}
	}
	sink.mu.Unlock()
	if !sawUpload {
		t.Fatal("SFTP upload was not recorded")
	}
	scp, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	output, e := scp.CombinedOutput("scp -t /tmp/file")
	if e == nil || !strings.Contains(string(output), "disabled") {
		t.Fatalf("scp should be rejected: %v %q", e, output)
	}
	_ = client.Close()
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}
