package upstream

import (
	"sync"
)

// connsPool - very simple array-based connections pool
type connsPool struct {
	closed bool    // if connsPool is closed, Put() and Get() do nothing
	conns  []*Conn // LIFO collection for connections
	sync.Mutex
}

func (p *connsPool) Get() *Conn {
	p.Lock()
	if p.closed {
		p.Unlock()
		return nil
	}

	var conn *Conn
	if len(p.conns) > 0 {
		n := len(p.conns) - 1 // Top element
		conn = p.conns[n]     // Get the top element
		p.conns[n] = nil      // Erase element to avoid leaks
		p.conns = p.conns[:n] // Pop
	}
	p.Unlock()
	return conn
}

func (p *connsPool) Put(conn *Conn) {
	p.Lock()
	if p.closed {
		p.Unlock()
		return
	}

	p.conns = append(p.conns, conn)
	p.Unlock()
}

func (p *connsPool) Close() {
	p.Lock()
	p.closed = true
	for _, conn := range p.conns {
		_ = conn.Close()
	}
	p.Unlock()
}
