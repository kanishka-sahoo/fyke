// Package model defines the versioned, protocol-neutral evidence model shared by
// every sensor and the controller. Sensitive bytes are carried separately and
// sealed by the controller before persistence.
package model

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const SchemaVersion uint32 = 1

type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type Evidence struct {
	Kind        string `json:"kind"`
	ContentType string `json:"content_type,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Data        []byte `json:"data,omitempty"`
}

type Event struct {
	ID           string         `json:"id"`
	Timestamp    time.Time      `json:"timestamp"`
	Schema       uint32         `json:"schema_version"`
	SensorID     string         `json:"sensor_id"`
	SessionID    string         `json:"session_id"`
	Sequence     uint64         `json:"sequence"`
	Source       Endpoint       `json:"source"`
	Destination  Endpoint       `json:"destination"`
	Protocol     string         `json:"protocol"`
	Type         string         `json:"event_type"`
	Outcome      string         `json:"outcome"`
	Persona      string         `json:"persona"`
	Attributes   map[string]any `json:"attributes,omitempty"`
	ProtocolData map[string]any `json:"protocol_attributes,omitempty"`
	Evidence     []Evidence     `json:"evidence,omitempty"`
}

func (e *Event) Normalize(now time.Time) error {
	if e.ID == "" {
		e.ID = NewUUIDv7(now)
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = now.UTC()
	}
	e.Timestamp = e.Timestamp.UTC()
	if e.Schema == 0 {
		e.Schema = SchemaVersion
	}
	if e.Schema != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", e.Schema)
	}
	if e.SensorID == "" || e.SessionID == "" || e.Protocol == "" || e.Type == "" {
		return fmt.Errorf("sensor_id, session_id, protocol, and event_type are required")
	}
	if e.Source.IP != "" {
		if _, err := netip.ParseAddr(e.Source.IP); err != nil {
			return fmt.Errorf("source ip: %w", err)
		}
	}
	if e.Destination.IP != "" {
		if _, err := netip.ParseAddr(e.Destination.IP); err != nil {
			return fmt.Errorf("destination ip: %w", err)
		}
	}
	e.Protocol = strings.ToLower(e.Protocol)
	return nil
}

var uuidMu sync.Mutex
var lastMS uint64
var lastRand [10]byte

// NewUUIDv7 returns a monotonically increasing RFC 9562 UUIDv7 within this
// process, including when several events share the same millisecond.
func NewUUIDv7(t time.Time) string {
	uuidMu.Lock()
	defer uuidMu.Unlock()
	ms := uint64(t.UnixMilli())
	if ms > lastMS {
		lastMS = ms
		_, _ = rand.Read(lastRand[:])
	} else {
		ms = lastMS
		for i := len(lastRand) - 1; i >= 0; i-- {
			lastRand[i]++
			if lastRand[i] != 0 {
				break
			}
		}
	}
	var b [16]byte
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	copy(b[6:], lastRand[:])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func EventKey(sensorID, sessionID string, sequence uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sequence)
	return sensorID + "\x00" + sessionID + "\x00" + string(b[:])
}
