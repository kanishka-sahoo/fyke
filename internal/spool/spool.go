// Package spool is a crash-safe encrypted queue. Each record is atomic and is
// removed only after a controller acknowledgement. Unacknowledged evidence is
// never silently evicted: producers receive ErrFull and apply backpressure.
package spool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrFull = errors.New("encrypted sensor spool is full")

type Record struct {
	ID   string
	Data []byte
}
type Spool struct {
	mu   sync.Mutex
	dir  string
	max  int64
	aead cipher.AEAD
	used int64
	wake chan struct{}
}

func Open(dir string, max int64) (*Spool, error) {
	if max < 1<<20 {
		return nil, fmt.Errorf("spool limit too small")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	keyPath := filepath.Join(dir, ".key")
	key, e := os.ReadFile(keyPath)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		if e = os.WriteFile(keyPath, key, 0600); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid spool key")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	s := &Spool{dir: dir, max: max, aead: aead, wake: make(chan struct{}, 1)}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	for _, x := range entries {
		if strings.HasSuffix(x.Name(), ".rec") {
			info, _ := x.Info()
			s.used += info.Size()
		}
	}
	return s, nil
}
func (s *Spool) Put(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nonce := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	sealed := append(nonce, s.aead.Seal(nil, nonce, data, []byte(id))...)
	if s.used+int64(len(sealed)) > s.max {
		return ErrFull
	}
	name := fmt.Sprintf("%020d-%s.rec", time.Now().UnixNano(), hex.EncodeToString([]byte(id)))
	tmp := filepath.Join(s.dir, "."+name+".tmp")
	dst := filepath.Join(s.dir, name)
	if e := os.WriteFile(tmp, sealed, 0600); e != nil {
		return e
	}
	if e := os.Rename(tmp, dst); e != nil {
		return e
	}
	s.used += int64(len(sealed))
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}
func (s *Spool) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, e := os.ReadDir(s.dir)
	if e != nil {
		return nil, e
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []Record
	for _, x := range entries {
		if !strings.HasSuffix(x.Name(), ".rec") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(x.Name(), ".rec"), "-")
		if len(parts) != 2 {
			continue
		}
		idb, e := hex.DecodeString(parts[1])
		if e != nil {
			continue
		}
		id := string(idb)
		sealed, e := os.ReadFile(filepath.Join(s.dir, x.Name()))
		if e != nil {
			return nil, e
		}
		n := s.aead.NonceSize()
		if len(sealed) < n {
			return nil, fmt.Errorf("corrupt spool record %s", x.Name())
		}
		data, e := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(id))
		if e != nil {
			return nil, fmt.Errorf("decrypt spool record: %w", e)
		}
		out = append(out, Record{ID: id, Data: data})
	}
	return out, nil
}
func (s *Spool) Ack(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	suffix := "-" + hex.EncodeToString([]byte(id)) + ".rec"
	entries, e := os.ReadDir(s.dir)
	if e != nil {
		return e
	}
	for _, x := range entries {
		if strings.HasSuffix(x.Name(), suffix) {
			info, _ := x.Info()
			if e = os.Remove(filepath.Join(s.dir, x.Name())); e != nil {
				return e
			}
			s.used -= info.Size()
			return nil
		}
	}
	return nil
}
func (s *Spool) Wake() <-chan struct{} { return s.wake }
func (s *Spool) Used() int64           { s.mu.Lock(); defer s.mu.Unlock(); return s.used }
