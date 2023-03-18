package dnsservertest

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/logging"
)

// QUICTracer implements the logging.Tracer interface.
type QUICTracer struct {
	logging.NullTracer
	tracers []*quicConnTracer

	// mu protects fields of *QUICTracer and also protects fields of every
	// nested *quicConnTracer.
	mu sync.Mutex
}

// type check
var _ logging.Tracer = (*QUICTracer)(nil)

// TracerForConnection implements the logging.Tracer interface for *quicTracer.
func (q *QUICTracer) TracerForConnection(
	_ context.Context,
	_ logging.Perspective,
	odcid logging.ConnectionID,
) (connTracer logging.ConnectionTracer) {
	q.mu.Lock()
	defer q.mu.Unlock()

	tracer := &quicConnTracer{id: odcid, parent: q}
	q.tracers = append(q.tracers, tracer)

	return tracer
}

// QUICConnInfo contains information about packets that were recorded by
// *QUICTracer.
type QUICConnInfo struct {
	id      logging.ConnectionID
	packets []logging.Header
}

// Is0RTT returns true if this connection's packets contain 0-RTT packets.
func (c *QUICConnInfo) Is0RTT() (ok bool) {
	for _, packet := range c.packets {
		hdr := packet
		packetType := logging.PacketTypeFromHeader(&hdr)
		if packetType == logging.PacketType0RTT {
			return true
		}
	}

	return false
}

// ConnectionsInfo returns the traced connections' information.
func (q *QUICTracer) ConnectionsInfo() (conns []QUICConnInfo) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, tracer := range q.tracers {
		conns = append(conns, QUICConnInfo{
			id:      tracer.id,
			packets: tracer.packets,
		})
	}

	return conns
}

// quicConnTracer implements the [logging.ConnectionTracer] interface.
type quicConnTracer struct {
	id      logging.ConnectionID
	parent  *QUICTracer
	packets []logging.Header

	logging.NullConnectionTracer
}

// type check
var _ logging.ConnectionTracer = (*quicConnTracer)(nil)

// SentLongHeaderPacket implements the [logging.ConnectionTracer] interface for
// *quicConnTracer.
func (q *quicConnTracer) SentLongHeaderPacket(
	hdr *logging.ExtendedHeader,
	_ logging.ByteCount,
	_ *logging.AckFrame,
	_ []logging.Frame,
) {
	q.parent.mu.Lock()
	defer q.parent.mu.Unlock()

	q.packets = append(q.packets, hdr.Header)
}
