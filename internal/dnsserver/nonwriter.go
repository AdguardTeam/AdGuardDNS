package dnsserver

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// NonWriterResponseWriter saves the response that has been written but doesn't
// actually send it to the client.
type NonWriterResponseWriter struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	resp       *dns.Msg
}

// NewNonWriterResponseWriter returns a new properly initialized
// *NonWriterResponseWriter.
func NewNonWriterResponseWriter(localAddr, remoteAddr net.Addr) (nrw *NonWriterResponseWriter) {
	return &NonWriterResponseWriter{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// type check
var _ ResponseWriter = (*NonWriterResponseWriter)(nil)

// LocalAddr implements the [ResponseWriter] interface for
// *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) LocalAddr() (addr net.Addr) {
	return r.localAddr
}

// RemoteAddr implements the [ResponseWriter] interface for
// *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.remoteAddr
}

// WriteMsg implements the [ResponseWriter] interface for
// *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) WriteMsg(_ context.Context, _, resp *dns.Msg) (err error) {
	r.resp = resp

	return nil
}

// Resp returns the message that has been written.
func (r *NonWriterResponseWriter) Resp() (m *dns.Msg) {
	return r.resp
}
