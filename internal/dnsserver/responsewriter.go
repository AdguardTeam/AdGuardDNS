package dnsserver

import (
	"context"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// A ResponseWriter interface is used by a DNS handler to construct a DNS
// response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server.
	LocalAddr() net.Addr

	// RemoteAddr returns the net.Addr of the client that sent the current
	// request.
	RemoteAddr() net.Addr

	// WriteMsg writes a reply back to the client.  Handlers must not modify req
	// and resp after the call to WriteMsg, since their ResponseWriter
	// implementation may be a recorder.  req and resp must not be nil.
	//
	// TODO(a.garipov):  Store bytes written to the socket.
	WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error)
}

// RecorderResponseWriter implements the [ResponseWriter] interface and simply
// calls underlying writer's methods except for WriteMsg, which records a clone
// of the response message that has been written.
type RecorderResponseWriter struct {
	// rw is the underlying ResponseWriter.
	rw ResponseWriter

	// Resp is the response that has been written (if any).
	Resp *dns.Msg
}

// NewRecorderResponseWriter creates a new instance of RecorderResponseWriter.
func NewRecorderResponseWriter(rw ResponseWriter) (recw *RecorderResponseWriter) {
	return &RecorderResponseWriter{
		rw: rw,
	}
}

// type check
var _ ResponseWriter = (*RecorderResponseWriter)(nil)

// LocalAddr implements the [ResponseWriter] interface for
// *RecorderResponseWriter.
func (r *RecorderResponseWriter) LocalAddr() (addr net.Addr) {
	return r.rw.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for
// *RecorderResponseWriter.
func (r *RecorderResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.rw.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for
// *RecorderResponseWriter.
func (r *RecorderResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	defer func() { err = errors.Annotate(err, "recorder: %w") }()

	r.Resp = resp

	return r.rw.WriteMsg(ctx, req, resp)
}
