// Package internal contains common utilities for DNS middlewares.
package internal

import "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"

// MakeNonWriter makes rw a *dnsserver.NonWriterResponseWriter unless it already
// is one, in which case it just returns it.
func MakeNonWriter(rw dnsserver.ResponseWriter) (nwrw *dnsserver.NonWriterResponseWriter) {
	nwrw, ok := rw.(*dnsserver.NonWriterResponseWriter)
	if ok {
		return nwrw
	}

	return dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
}
