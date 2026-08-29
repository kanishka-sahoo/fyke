package ops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/store"
)

func TestBackupRestoreManifest(t *testing.T) {
	root := t.TempDir()
	controllerID := filepath.Join(root, "controller.agekey")
	cryptokit.GenerateIdentity(controllerID)
	seal, _ := cryptokit.Load(controllerID)
	data := filepath.Join(root, "data")
	st, e := store.Open(data, seal)
	if e != nil {
		t.Fatal(e)
	}
	event := model.Event{SensorID: "s", SessionID: "x", Sequence: 1, Protocol: "ssh", Type: "session.start", Evidence: []model.Evidence{{Kind: "transcript", Data: []byte("sealed")}}}
	if e = st.Insert(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	st.Close()
	recovery, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	recoveryFile := filepath.Join(root, "recovery.key")
	if e = os.WriteFile(recoveryFile, []byte(recovery.String()+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(root, "backup.age")
	c := config.Config{DataDir: data, Controller: config.Controller{Identity: controllerID}}
	if e = Backup(context.Background(), c, recovery.Recipient().String(), archive); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "restored")
	if e = Restore(archive, recoveryFile, target); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(target, "fyke.db")); e != nil {
		t.Fatal("database not restored")
	}
	matches, _ := filepath.Glob(filepath.Join(target, "artifacts", "*", "*.age"))
	if len(matches) != 1 {
		t.Fatalf("restored artifacts=%d", len(matches))
	}
}
