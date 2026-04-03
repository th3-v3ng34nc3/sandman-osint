package sse

import "sync"

// Event is the envelope sent over an SSE stream.
type Event struct {
	Name string `json:"event"`
	Data any    `json:"data"`
}

// Broker manages SSE subscriptions per query ID.
// All methods are safe for concurrent use.
type Broker struct {
	mu      sync.RWMutex
	clients map[string][]chan Event
}

// NewBroker creates an empty broker.
func NewBroker() *Broker {
	return &Broker{clients: make(map[string][]chan Event)}
}

// Subscribe registers a new listener for queryID.
// The returned channel receives events published for that query.
// Call the returned unsubscribe function when done.
func (b *Broker) Subscribe(queryID string) (<-chan Event, func()) {
	ch := make(chan Event, 128)

	b.mu.Lock()
	b.clients[queryID] = append(b.clients[queryID], ch)
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		chans := b.clients[queryID]
		for i, c := range chans {
			if c == ch {
				b.clients[queryID] = append(chans[:i], chans[i+1:]...)
				break
			}
		}
		close(ch)
		if len(b.clients[queryID]) == 0 {
			delete(b.clients, queryID)
		}
	}

	return ch, unsubscribe
}

// Publish sends an event to all subscribers of queryID.
// It never blocks — if a subscriber's buffer is full the event is dropped.
func (b *Broker) Publish(queryID string, event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients[queryID] {
		select {
		case ch <- event:
		default:
		}
	}
}
