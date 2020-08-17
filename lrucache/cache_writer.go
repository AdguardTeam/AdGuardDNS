package lrucache

import (
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

// Recorder is a type of ResponseWriter that captures
// the rcode code written to it and also the size of the message
// written in the response. A rcode code does not have
// to be written, however, in which case 0 must be assumed.
// It is best to have the constructor initialize this type
// with that default status code.
type CacheWriter struct {
	dns.ResponseWriter
	cache *cache
}

// WriteMsg records the status code and calls the
// underlying ResponseWriter's WriteMsg method.
func (r *CacheWriter) WriteMsg(res *dns.Msg) error {
	r.cache.Set(res)
	return r.ResponseWriter.WriteMsg(res)
}

// Write is a wrapper that records the length of the message that gets written.
func (r *CacheWriter) Write(buf []byte) (int, error) {
	clog.Debugf("Caching called with Write: not caching reply")
	// Not caching in this case
	return r.ResponseWriter.Write(buf)
}
