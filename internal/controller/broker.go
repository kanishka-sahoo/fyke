package controller

import (
	"encoding/json"
	"github.com/ksahoo/fyke/internal/model"
	"sync"
)

type Broker struct {
	mu   sync.Mutex
	next uint64
	subs map[uint64]chan []byte
}

func NewBroker() *Broker { return &Broker{subs: map[uint64]chan []byte{}} }
func (b *Broker) Publish(e model.Event) {
	data, _ := json.Marshal(e)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- data:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- data:
			default:
			}
		}
	}
}
func (b *Broker) Subscribe() (uint64, <-chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	ch := make(chan []byte, 128)
	b.subs[b.next] = ch
	return b.next, ch
}
func (b *Broker) Unsubscribe(id uint64) {
	b.mu.Lock()
	if ch, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(ch)
	}
	b.mu.Unlock()
}
