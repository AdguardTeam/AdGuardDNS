// Package pool is a simple net.Conn pool implementation.
package pool

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// ErrClosed indicates that the Pool is closed and cannot be used anymore.
const ErrClosed = errors.Error("the pool is closed")

// Factory is a type for the Pool's factory method. Factory implementation
// must use the context's deadline if it's specified.
type Factory func(ctx context.Context) (conn net.Conn, err error)

// Pool is a structure that implements a net.Conn pool. Must be initialized
// using the NewPool method.
type Pool struct {
	// IdleTimeout is the maximum TTL of an idle connection in the pool.
	// Connections that weren't used for more than the specified duration will
	// be closed. If set to 0, connections don't expire. Default value is 0.
	IdleTimeout time.Duration

	// connsChan is the storage for our connections.
	connsChan   chan *Conn
	connsChanMu sync.RWMutex

	// factory is the Pool's factory method. It is called whenever there are no
	// more connections in the pool.
	factory Factory
}

// NewPool creates a new Pool instance. maxCapacity configures the maximum
// number of idle connections in the pool. If the pool is full,
// Put will close the connection instead of adding it to the pool.
func NewPool(maxCapacity int, factory Factory) (p *Pool) {
	return &Pool{
		connsChan: make(chan *Conn, maxCapacity),
		factory:   factory,
	}
}

// Get returns a free connection from the pool. If there are no connections it
// will use the Factory method to create a new one.
func (p *Pool) Get(ctx context.Context) (conn *Conn, err error) {
	p.connsChanMu.RLock()
	connsChan := p.connsChan
	p.connsChanMu.RUnlock()

	if connsChan == nil {
		return nil, ErrClosed
	}

	for {
		select {
		case conn = <-connsChan:
			if conn == nil {
				return nil, ErrClosed
			}

			if isExpired(conn, p.IdleTimeout) {
				// Close the expired connection immediately and look for a new
				// one. Ignoring the error here since it's not important what
				// happens with it and I'd like to avoid logging
				_ = conn.Close()
				continue
			}

			conn.lastTimeUsed = time.Now()

			return conn, nil
		default:
			return p.Create(ctx)
		}
	}
}

// Put puts the connection back to the pool. If the pool is closed,
// the connection will be simply closed instead.
func (p *Pool) Put(conn *Conn) (err error) {
	p.connsChanMu.RLock()
	connsChan := p.connsChan
	p.connsChanMu.RUnlock()

	if connsChan == nil {
		// The pool is closed, simply close the connection.
		return p.closeConn(conn)
	}

	// Put the connection back into the pool.
	select {
	case connsChan <- conn:
		return nil
	default:
		return conn.Close()
	}
}

// Close closes the Pool. After that it cannot be used anymore, every method
// will return ErrClosed.
func (p *Pool) Close() (err error) {
	p.connsChanMu.Lock()
	defer p.connsChanMu.Unlock()

	if p.connsChan == nil {
		return ErrClosed
	}

	var errs []error
	close(p.connsChan)
	for conn := range p.connsChan {
		err = conn.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	// This marks the pool as closed.
	p.connsChan = nil

	return errors.Annotate(errors.Join(errs...), "closing pool: %w")
}

// closeConn is used when the pool is closed. In this case we attempt to close
// the connection immediately.
func (p *Pool) closeConn(conn *Conn) (err error) {
	err = conn.Close()
	if err != nil {
		return errors.WithDeferred(fmt.Errorf("closing pool connection: %w", err), ErrClosed)
	}

	return ErrClosed
}

// Create returns a new *Conn instance.
func (p *Pool) Create(ctx context.Context) (c *Conn, err error) {
	var netConn net.Conn
	netConn, err = p.factory(ctx)
	if err != nil {
		return nil, err
	}

	return wrapConn(netConn), nil
}
