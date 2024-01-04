package dnsservertest

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/logging"
)

// QUICTracer is a helper structure for tracing QUIC connections.
type QUICTracer struct {
	// mu protects fields of *QUICTracer and also protects fields of every
	// nested *quicConnTracer.
	mu *sync.Mutex

	connTracers []*quicConnTracer
}

// NewQUICTracer returns a new QUIC tracer helper.
func NewQUICTracer() (t *QUICTracer) {
	return &QUICTracer{
		mu: &sync.Mutex{},
	}
}

// TracerForConnection implements the logging.Tracer interface for *quicTracer.
func (t *QUICTracer) TracerForConnection(
	_ context.Context,
	_ logging.Perspective,
	_ logging.ConnectionID,
) (connTracer *logging.ConnectionTracer) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ct := &quicConnTracer{
		parentMu: t.mu,
	}

	t.connTracers = append(t.connTracers, ct)

	return &logging.ConnectionTracer{
		SentLongHeaderPacket: ct.SentLongHeaderPacket,
	}
}

// ConnectionsInfo returns the traced connections' information.
func (t *QUICTracer) ConnectionsInfo() (conns []*QUICConnInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tracer := range t.connTracers {
		conns = append(conns, &QUICConnInfo{
			headers: tracer.headers,
		})
	}

	return conns
}

// QUICConnInfo contains information about packets that were recorded by a
// [QUICTracer].
type QUICConnInfo struct {
	headers []*logging.Header
}

// Is0RTT returns true if this connection's packets contain 0-RTT packets.
func (c *QUICConnInfo) Is0RTT() (ok bool) {
	for _, hdr := range c.headers {
		if t := logging.PacketTypeFromHeader(hdr); t == logging.PacketType0RTT {
			return true
		}
	}

	return false
}

// quicConnTracer is a helper structure for tracing QUIC connections.
type quicConnTracer struct {
	parentMu *sync.Mutex
	headers  []*logging.Header
}

// SentLongHeaderPacket is a method for the [logging.ConnectionTracer] method.
func (q *quicConnTracer) SentLongHeaderPacket(
	extHdr *logging.ExtendedHeader,
	_ logging.ByteCount,
	_ logging.ECN,
	_ *logging.AckFrame,
	_ []logging.Frame,
) {
	q.parentMu.Lock()
	defer q.parentMu.Unlock()

	hdr := extHdr.Header
	q.headers = append(q.headers, &hdr)
}
