package ops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ksahoo/fyke/internal/config"
)

func TestDoctorValidatesGeneratedDeployment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	if e := Init(root); e != nil {
		t.Fatal(e)
	}
	c, e := config.Load(filepath.Join(root, "config.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	if e = Doctor(c); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(root, "pki", "sensor-ssh.key")
	if e = os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	if e = Doctor(c); e == nil {
		t.Fatal("Doctor accepted a world-readable sensor private key")
	}
}
