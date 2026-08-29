package model

import (
	"strings"
	"testing"
	"time"
)

func TestUUIDv7MonotonicAndVersioned(t *testing.T) {
	now := time.UnixMilli(1700000000123)
	a := NewUUIDv7(now)
	b := NewUUIDv7(now)
	if a >= b {
		t.Fatalf("ids are not monotonic: %s >= %s", a, b)
	}
	if len(a) != 36 || a[14] != '7' || !strings.Contains(a, "-") {
		t.Fatalf("not UUIDv7: %s", a)
	}
}
func TestNormalizeRejectsBadAddress(t *testing.T) {
	e := Event{SensorID: "s", SessionID: "x", Protocol: "ssh", Type: "session", Source: Endpoint{IP: "not an ip"}}
	if e.Normalize(time.Now()) == nil {
		t.Fatal("accepted invalid source")
	}
}
