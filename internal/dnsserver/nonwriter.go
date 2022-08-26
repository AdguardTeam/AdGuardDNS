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
	req        *dns.Msg // request (should be supplied in the WriteMsg method)
	res        *dns.Msg // message that has been written (if any)
}

// type check
var _ ResponseWriter = (*NonWriterResponseWriter)(nil)

// NewNonWriterResponseWriter creates a new instance of the NonWriterResponseWriter.
func NewNonWriterResponseWriter(localAddr, remoteAddr net.Addr) (nrw *NonWriterResponseWriter) {
	return &NonWriterResponseWriter{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// LocalAddr implements the ResponseWriter interface for *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) LocalAddr() (addr net.Addr) {
	return r.localAddr
}

// RemoteAddr implements the ResponseWriter interface for *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.remoteAddr
}

// WriteMsg implements the ResponseWriter interface for *NonWriterResponseWriter.
func (r *NonWriterResponseWriter) WriteMsg(_ context.Context, req, resp *dns.Msg) (err error) {
	// Just save the response, we'll use it later (see httpHandler for instance)
	r.req = req
	r.res = resp

	return nil
}

// Msg returns the message that has been written.
func (r *NonWriterResponseWriter) Msg() (m *dns.Msg) {
	return r.res
}
