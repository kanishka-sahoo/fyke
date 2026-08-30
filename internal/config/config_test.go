package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	b := `
controller:
  identity: identity
  tls: {cert: cert, key: key, ca: ca}
unexpected_option: true
`
	if e := os.WriteFile(file, []byte(b), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := Load(file)
	if e == nil || !strings.Contains(e.Error(), "unexpected_option") {
		t.Fatalf("Load() error = %v, want unknown-field error", e)
	}
}

func TestAlertsValidate(t *testing.T) {
	if e := (Alerts{Webhooks: []string{"http://example.com"}}).Validate(); e == nil {
		t.Fatal("insecure webhook was accepted")
	}
	if e := (Alerts{Webhooks: []string{"https://example.com/hook"}, SourceSpikePerMinute: 10}).Validate(); e != nil {
		t.Fatal(e)
	}
}
