package dnsservertest

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// CreateTestHandler creates a [dnsserver.Handler] with the specified parameters.
func CreateTestHandler(recordsCount int) (h dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		// Check that necessary context keys are set.
		si := dnsserver.MustServerInfoFromContext(ctx)
		_ = dnsserver.MustStartTimeFromContext(ctx)
		ci := dnsserver.MustClientInfoFromContext(ctx)
		if si.Proto.IsStdEncrypted() && ci.TLSServerName == "" {
			return errors.Error("client info does not contain server name")
		}

		hostname := req.Question[0].Name

		resp := &dns.Msg{
			Compress: true,
		}
		resp.SetReply(req)

		for i := 0; i < recordsCount; i++ {
			hdr := dns.RR_Header{
				Name:   hostname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    100,
			}

			a := &dns.A{
				// Add 1 to make sure that each IP is valid.
				A:   net.IP{127, 0, 0, byte(i + 1)},
				Hdr: hdr,
			}

			resp.Answer = append(resp.Answer, a)
		}

		_ = rw.WriteMsg(ctx, req, resp)

		return nil
	}

	return dnsserver.HandlerFunc(f)
}

// DefaultHandler returns a simple handler that always returns a response with
// a single A record.
func DefaultHandler() (handler dnsserver.Handler) {
	return CreateTestHandler(1)
}
