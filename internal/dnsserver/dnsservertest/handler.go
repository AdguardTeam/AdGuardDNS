package dnsservertest

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// AnswerTTL is the default TTL of the test handler's answers.
const AnswerTTL time.Duration = 100 * time.Second

// CreateTestHandler creates a [dnsserver.Handler] with the specified
// parameters.  All responses will have the [TestAnsTTL] TTL.
func CreateTestHandler(recordsCount int) (h dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		// Check that necessary context keys are set.
		si := dnsserver.MustServerInfoFromContext(ctx)
		ri := dnsserver.MustRequestInfoFromContext(ctx)
		if si.Proto.IsStdEncrypted() && ri.TLSServerName == "" {
			return errors.Error("client info does not contain server name")
		}

		ans := make(SectionAnswer, 0, recordsCount)
		hdr := dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(AnswerTTL.Seconds()),
		}

		ip := netutil.IPv4Localhost().Prev()
		for i := 0; i < recordsCount; i++ {
			// Add 1 to make sure that each IP is valid.
			ip = ip.Next()
			ans = append(ans, &dns.A{Hdr: hdr, A: ip.AsSlice()})
		}

		resp := NewResp(dns.RcodeSuccess, req, ans)

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
