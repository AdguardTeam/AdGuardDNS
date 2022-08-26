package dnsserver

import (
	"context"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// RecorderResponseWriter implements the ResponseWriter interface and simply
// calls underlying ResponseWriter functions except for the WriteMsg method,
// which records a clone of the response message that has been written.
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

// LocalAddr implements the ResponseWriter interface for *RecorderResponseWriter.
func (r *RecorderResponseWriter) LocalAddr() (addr net.Addr) {
	return r.rw.LocalAddr()
}

// RemoteAddr implements the ResponseWriter interface for *RecorderResponseWriter.
func (r *RecorderResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.rw.RemoteAddr()
}

// WriteMsg implements the ResponseWriter interface for *RecorderResponseWriter.
func (r *RecorderResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	defer func() { err = errors.Annotate(err, "recorder: %w") }()

	r.Resp = resp

	return r.rw.WriteMsg(ctx, req, resp)
}
