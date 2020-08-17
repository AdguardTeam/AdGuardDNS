package dnsdb

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// plug represents the plugin itself
type plug struct {
	Next plugin.Handler

	addr string // Address for the HTTP server that serves the DB data
	path string // Path to the DNSDB instance
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (p *plug) Name() string { return "dnsdb" }

// ServeDNS handles the DNS request and records it to the DNSDB
func (p *plug) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	cw := &DBWriter{
		ResponseWriter: w,
		db:             dnsDBMap[p.addr],
	}
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, cw, r)
}

// Recorder is a type of ResponseWriter that captures
// the rcode code written to it and also the size of the message
// written in the response. A rcode code does not have
// to be written, however, in which case 0 must be assumed.
// It is best to have the constructor initialize this type
// with that default status code.
type DBWriter struct {
	dns.ResponseWriter
	db *dnsDB
}

// WriteMsg records the status code and calls the
// underlying ResponseWriter's WriteMsg method.
func (r *DBWriter) WriteMsg(res *dns.Msg) error {
	r.db.RecordMsg(res)
	return r.ResponseWriter.WriteMsg(res)
}

// Write is a wrapper that records the length of the message that gets written.
func (r *DBWriter) Write(buf []byte) (int, error) {
	// Doing nothing in this case
	return r.ResponseWriter.Write(buf)
}
