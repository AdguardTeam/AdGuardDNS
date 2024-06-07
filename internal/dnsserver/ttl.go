package dnsserver

import (
	"time"

	"github.com/miekg/dns"
)

const (
	// minimalDefaultTTL is the absolute lowest TTL we can use.
	minimalDefaultTTL = 5 * time.Second
	// maximumDefaultTTL is the maximum TTL was use on RRsets.
	maximumDefaultTTL = 1 * time.Hour
)

// minimalTTL scans the message and returns the lowest TTL found.
func minimalTTL(m *dns.Msg) (d time.Duration) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return minimalDefaultTTL
	}

	// If message is empty, i.e. there are no records with TTL
	// return a short ttl as a fail safe.
	if isEmptyMessage(m) {
		return minimalDefaultTTL
	}

	return minimalTTLMsgRRs(m)
}

// isEmptyRequest returns true if the message has no records at all
// or if it has just an OPT record.  We consider it an "empty" message
// in this case.
func isEmptyMessage(m *dns.Msg) (empty bool) {
	return len(m.Answer) == 0 && len(m.Ns) == 0 &&
		(len(m.Extra) == 0 ||
			(len(m.Extra) == 1 && m.Extra[0].Header().Rrtype == dns.TypeOPT))
}

// minimalTTLMsgRRs gets minimal TTL from all message RRs.
func minimalTTLMsgRRs(m *dns.Msg) (d time.Duration) {
	minTTL32 := uint32(maximumDefaultTTL.Seconds())

	for _, r := range m.Answer {
		minTTL32 = min(minTTL32, r.Header().Ttl)
	}

	for _, r := range m.Ns {
		minTTL32 = min(minTTL32, r.Header().Ttl)
	}

	for _, r := range m.Extra {
		// OPT records use TTL field for extended rcode and flags.
		if h := r.Header(); h.Rrtype != dns.TypeOPT {
			minTTL32 = min(minTTL32, h.Ttl)
		}
	}

	return time.Duration(minTTL32) * time.Second
}
