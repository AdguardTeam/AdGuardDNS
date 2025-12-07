package dnsservertest

import (
	"context"
	"slices"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Tracer collects QUIC connection traces for testing.
//
// TODO(f.setrakov): Consider moving to golibs.
type Tracer struct {
	tracers []*quicTracer
}

// TraceForConnection creates a tracer for a QUIC connection.
func (t *Tracer) TraceForConnection(
	_ context.Context,
	_ bool,
	_ quic.ConnectionID,
) (tracer qlogwriter.Trace) {
	newTracer := &quicTracer{recorder: &headerRecorder{}}
	t.tracers = append(t.tracers, newTracer)

	return newTracer
}

// ConnectionsInfo returns info for all traced connections.
func (t *Tracer) ConnectionsInfo() (res []*connInfo) {
	res = make([]*connInfo, 0, len(t.tracers))
	for _, tracer := range t.tracers {
		hdrs := tracer.recorder.headersWithLock()

		res = append(res, &connInfo{
			headers: hdrs,
		})
	}

	return res
}

// connInfo contains all trace event headers recorded for single connection.
type connInfo struct {
	headers []qlog.PacketHeader
}

// Is0RTT returns true if the connection used 0-RTT packets.
func (c *connInfo) Is0RTT() (ok bool) {
	for _, hdr := range c.headers {
		if hdr.PacketType == qlog.PacketType0RTT {
			return true
		}
	}

	return false
}

// quicTracer is an implementation of [qlogwriter.Trace] for testing.
type quicTracer struct {
	// recorder is used for recording trace events.  It must not be nil.
	recorder *headerRecorder
}

// type check
var _ qlogwriter.Trace = (*quicTracer)(nil)

// AddProducer implements the [qlogwriter.Trace] interface for *quicTracer.
func (q *quicTracer) AddProducer() (recorder qlogwriter.Recorder) {
	return q.recorder
}

// SupportsSchemas implements the [qlogwriter.Trace] interface for *quicTracer.
func (q *quicTracer) SupportsSchemas(_ string) (ok bool) {
	return false
}

// Recorder is an implementation of [qlogwriter.Recorder] that records
// [qlog.PacketSent] events headers.
type headerRecorder struct {
	headers []qlog.PacketHeader
	mx      sync.Mutex
}

// type check
var _ qlogwriter.Recorder = (*headerRecorder)(nil)

// RecordEvent implements the [qlogwriter.Recorder] interface for
// *headerRecorder.
func (r *headerRecorder) RecordEvent(ev qlogwriter.Event) {
	event, ok := ev.(qlog.PacketSent)
	if !ok {
		return
	}

	r.mx.Lock()
	defer r.mx.Unlock()

	r.headers = append(r.headers, event.Header)
}

// headersWithLock returns copy of recorded headers.  It is safe for concurrent
// use.
func (r *headerRecorder) headersWithLock() (res []qlog.PacketHeader) {
	r.mx.Lock()
	defer r.mx.Unlock()

	return slices.Clone(r.headers)
}

// Close implements the [qlogwriter.Recorder] interface for
// *headerRecorder.
func (*headerRecorder) Close() (err error) {
	return nil
}
