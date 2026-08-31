package ops

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/store"
)

type manifest struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Files     map[string]string `json:"files"`
}

func Backup(ctx context.Context, c config.Config, recipient, out string) error {
	if recipient == "" {
		return fmt.Errorf("operator recovery recipient required")
	}
	r, e := age.ParseX25519Recipient(recipient)
	if e != nil {
		return e
	}
	if _, e = os.Stat(out); e == nil {
		return fmt.Errorf("refusing to overwrite %s", out)
	}
	if _, e = cryptokit.Load(c.Controller.Identity); e != nil {
		return e
	}
	db, e := sql.Open("sqlite", filepath.Join(c.DataDir, "fyke.db")+"?_pragma=busy_timeout(10000)")
	if e != nil {
		return e
	}
	defer db.Close()
	if e = db.PingContext(ctx); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(out), ".fyke-backup-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	dbCopy := filepath.Join(tmp, "fyke.db")
	escaped := strings.ReplaceAll(dbCopy, "'", "''")
	if _, e = db.ExecContext(ctx, "VACUUM INTO '"+escaped+"'"); e != nil {
		return e
	}
	files := map[string]string{"database/fyke.db": dbCopy}
	e = filepath.Walk(filepath.Join(c.DataDir, "artifacts"), func(p string, i os.FileInfo, e error) error {
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if i.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(c.DataDir, p)
		if e != nil {
			return e
		}
		files[filepath.ToSlash(rel)] = p
		return nil
	})
	if e != nil {
		return e
	}
	m := manifest{Version: 1, CreatedAt: time.Now().UTC(), Files: map[string]string{}}
	for name, p := range files {
		sum, e := hashFile(p)
		if e != nil {
			return e
		}
		m.Files[name] = sum
	}
	mf, _ := json.MarshalIndent(m, "", "  ")
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(out)
		}
	}()
	aw, e := age.Encrypt(f, r)
	if e != nil {
		return e
	}
	tw := tar.NewWriter(aw)
	if e = tarBytes(tw, "manifest.json", mf, 0600); e != nil {
		return e
	}
	for name, p := range files {
		if e = tarFile(tw, name, p); e != nil {
			return e
		}
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = aw.Close(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
func Restore(backup, identity, target string) error {
	if entries, e := os.ReadDir(target); e == nil && len(entries) > 0 {
		return fmt.Errorf("restore target must be empty")
	}
	ib, e := os.ReadFile(identity)
	if e != nil {
		return e
	}
	ids, e := age.ParseIdentities(strings.NewReader(string(ib)))
	if e != nil {
		return e
	}
	f, e := os.Open(backup)
	if e != nil {
		return e
	}
	defer f.Close()
	ar, e := age.Decrypt(f, ids...)
	if e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(target), ".fyke-restore-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	tr := tar.NewReader(ar)
	var m manifest
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe archive path")
		}
		if name == "manifest.json" {
			if e = json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); e != nil {
				return e
			}
			continue
		}
		dst := filepath.Join(tmp, name)
		if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
			return e
		}
		w, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, copyErr := io.Copy(w, tr)
		closeErr := w.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if m.Version != 1 {
		return fmt.Errorf("unsupported or missing manifest")
	}
	for name, want := range m.Files {
		got, e := hashFile(filepath.Join(tmp, filepath.FromSlash(name)))
		if e != nil {
			return e
		}
		if got != want {
			return fmt.Errorf("backup hash mismatch for %s", name)
		}
	}
	if e = os.MkdirAll(target, 0700); e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(tmp, "database", "fyke.db"), filepath.Join(target, "fyke.db")); e != nil {
		return e
	}
	if _, e = os.Stat(filepath.Join(tmp, "artifacts")); e == nil {
		if e = os.Rename(filepath.Join(tmp, "artifacts"), filepath.Join(target, "artifacts")); e != nil {
			return e
		}
	}
	return nil
}
func Export(ctx context.Context, c config.Config, format, out string, sensitive bool, recipient string) error {
	sealer, e := cryptokit.Load(c.Controller.Identity)
	if e != nil {
		return e
	}
	st, e := store.Open(c.DataDir, sealer)
	if e != nil {
		return e
	}
	defer st.Close()
	if sensitive {
		if out == "" || recipient == "" {
			return fmt.Errorf("sensitive export requires --out and --recipient")
		}
		return exportInvestigationBundle(ctx, st, out, recipient)
	}
	var w io.Writer = os.Stdout
	var f *os.File
	if out != "" {
		f, e = os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		w = f
	}
	st.Audit(ctx, "events.export", "cli", map[string]any{"format": format, "sensitive": sensitive, "output": out})
	switch format {
	case "jsonl":
		enc := json.NewEncoder(w)
		_, e = st.ForEachSnapshot(ctx, store.Query{}, func(x store.EventRecord) error { return enc.Encode(x) })
		return e
	case "csv":
		cw := csv.NewWriter(w)
		if e = cw.Write([]string{"id", "timestamp", "sensor_id", "session_id", "source_ip", "protocol", "event_type", "outcome"}); e != nil {
			return e
		}
		_, e = st.ForEachSnapshot(ctx, store.Query{}, func(x store.EventRecord) error {
			return cw.Write([]string{x.ID, x.Timestamp.Format(time.RFC3339Nano), x.SensorID, x.SessionID, x.Source.IP, x.Protocol, x.Type, x.Outcome})
		})
		if e != nil {
			return e
		}
		cw.Flush()
		return cw.Error()
	default:
		return fmt.Errorf("format must be jsonl or csv")
	}
}

func exportInvestigationBundle(ctx context.Context, st *store.Store, out, recipient string) error {
	r, e := age.ParseX25519Recipient(recipient)
	if e != nil {
		return e
	}
	if _, e = os.Stat(out); e == nil {
		return fmt.Errorf("refusing to overwrite %s", out)
	}
	tmp, e := os.CreateTemp(filepath.Dir(out), ".fyke-investigation-events-")
	if e != nil {
		return e
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	enc := json.NewEncoder(tmp)
	var refs []store.EvidenceRef
	count, e := st.ForEachSnapshot(ctx, store.Query{}, func(x store.EventRecord) error {
		refs = append(refs, x.EvidenceRefs...)
		return enc.Encode(x)
	})
	if closeErr := tmp.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(out)
		}
	}()
	aw, e := age.Encrypt(f, r)
	if e != nil {
		return e
	}
	tw := tar.NewWriter(aw)
	meta, _ := json.MarshalIndent(map[string]any{"version": 1, "created_at": time.Now().UTC(), "events": count, "artifacts": len(refs)}, "", "  ")
	if e = tarBytes(tw, "manifest.json", meta, 0600); e != nil {
		return e
	}
	if e = tarFile(tw, "events.jsonl", tmpName); e != nil {
		return e
	}
	for _, ref := range refs {
		_, body, readErr := st.Evidence(ctx, ref.ID)
		if readErr != nil {
			return readErr
		}
		name := filepath.ToSlash(filepath.Join("artifacts", ref.ID, safeBundleName(ref.Filename)))
		if e = tarBytes(tw, name, body, 0600); e != nil {
			return e
		}
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = aw.Close(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return st.Audit(ctx, "investigation.bundle.export", "cli", map[string]any{"events": count, "artifacts": len(refs), "output": out})
}

func safeBundleName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "" || name == "." {
		return "evidence.bin"
	}
	return name
}
func hashFile(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func tarBytes(t *tar.Writer, name string, b []byte, mode int64) error {
	if e := t.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), ModTime: time.Now()}); e != nil {
		return e
	}
	_, e := t.Write(b)
	return e
}
func tarFile(t *tar.Writer, name, p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	if e = t.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: i.Size(), ModTime: i.ModTime()}); e != nil {
		return e
	}
	_, e = io.Copy(t, f)
	return e
}
