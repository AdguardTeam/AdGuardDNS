package ecscache

import (
	"fmt"
	"math"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

// Message Utilities
//
// TODO(a.garipov): Consider adding some of these functions to dnsmsg.

// rmHopToHopData removes hop-to-top data, such as DNSSEC RRs, from resp.
// reqDO tells whether the request had the DNSSEC OK (DO) bit set.
func rmHopToHopData(resp *dns.Msg, qt dnsmsg.RRType, reqDO bool) {
	// Filter out only DNSSEC RRs that aren't explicitly requested.
	//
	// See https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1 and
	// https://github.com/AdguardTeam/dnsproxy/issues/144.
	resp.Answer = rmHopToHopRRs(resp.Answer, reqDO, qt)
	resp.Ns = rmHopToHopRRs(resp.Ns, reqDO, dns.TypeNone)
	resp.Extra = rmHopToHopRRs(resp.Extra, reqDO, dns.TypeNone)
}

// rmHopToHopRRs removes OPT RRs unconditionally and removes DNSSEC RRs, with
// the exception of exc, if reqDO is false from rrs.  It returns filtered,
// a slice which has the same underlying storage as rrs.  The rest of rrs is
// filled with nils.
func rmHopToHopRRs(rrs []dns.RR, reqDO bool, exc uint16) (filtered []dns.RR) {
	filtered = rrs[:0:len(rrs)]
	for _, rr := range rrs {
		rrType := rr.Header().Rrtype
		if rrType != dns.TypeOPT && (reqDO || !isDNSSEC(rr) || rrType == exc) {
			filtered = append(filtered, rr)
		}
	}

	// Set the remaining items to nil to let the garbage collector do its job.
	for i := len(filtered); i < len(rrs); i++ {
		rrs[i] = nil
	}

	return filtered
}

// isDNSSEC returns true if rr is a DNSSEC RR.  NSEC, NSEC3, DS, DNSKEY and
// RRSIG/SIG are DNSSEC records.
func isDNSSEC(rr dns.RR) (ok bool) {
	switch rr.(type) {
	case
		*dns.NSEC,
		*dns.NSEC3,
		*dns.DS,
		*dns.RRSIG,
		*dns.SIG,
		*dns.DNSKEY:
		return true
	default:
		return false
	}
}

// setRespAD sets the Authenticated Data (AD) bit based on request data.
// reqAD and reqDO tell whether the request had the Authenticated Data (AD) and
// DNSSEC OK (DO) bits set.
//
// Per RFC 6840, validating resolvers should only set the AD bit when a response
// both meets the conditions listed in RFC 4035 and the request contained either
// a set DO bit or a set AD bit.
func setRespAD(resp *dns.Msg, reqAD, reqDO bool) {
	resp.AuthenticatedData = resp.AuthenticatedData && (reqAD || reqDO)
}

// setECS sets the EDNS Client Subnet option using data from ecs.  Both msg and
// ecs must not be nil.  ecsFam should be either agdnet.AddrFamilyIPv4 or
// agdnet.AddrFamilyIPv6.  ecs should contain an IP address of the same family
// as ecsFam.
func setECS(
	msg *dns.Msg,
	ecs *agd.ECS,
	ecsFam agdnet.AddrFamily,
	isResp bool,
) (err error) {
	ip, err := addrToNetIP(ecs.Subnet.Addr(), ecsFam)
	if err != nil {
		return fmt.Errorf("checking subnet ip: %w", err)
	}

	prefixLen := uint8(ecs.Subnet.Bits())

	var scope uint8
	if isResp {
		scope = prefixLen
	}

	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(dnsmsg.DefaultEDNSUDPSize, !isResp || msg.AuthenticatedData)
		opt = msg.Extra[len(msg.Extra)-1].(*dns.OPT)
	} else {
		opt.SetUDPSize(dnsmsg.DefaultEDNSUDPSize)

		for _, o := range opt.Option {
			if edns, ok := o.(*dns.EDNS0_SUBNET); ok {
				edns.SourceNetmask = prefixLen
				edns.SourceScope = scope
				edns.Address = ip

				return nil
			}
		}
	}

	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(ecsFam),
		SourceNetmask: prefixLen,
		SourceScope:   scope,
		Address:       ip,
	})

	return nil
}

// addrToNetIP returns ip as a net.IP with the correct number of bytes for fam.
// fam must be either agdnet.AddrFamilyIPv4 or agdnet.AddrFamilyIPv6.
func addrToNetIP(ip netip.Addr, fam agdnet.AddrFamily) (res net.IP, err error) {
	switch fam {
	case agdnet.AddrFamilyIPv4:
		if ip.Is6() {
			return nil, fmt.Errorf("cannot convert %s to ipv4", ip)
		}

		// Use a temporary variable to make the value addressable.  Don't use
		// AsSlice, since that would return a 16-byte form of the address.
		ip4 := ip.As4()

		return ip4[:], nil
	case agdnet.AddrFamilyIPv6:
		if ip.Is4() {
			return nil, fmt.Errorf("bad ipv4 addr %s for ipv6 addr fam", ip)
		}

		return ip.AsSlice(), nil
	default:
		return nil, fmt.Errorf("unsupported addr fam %s", fam)
	}
}

// isCacheable returns true if msg can be cached.  It doesn't consider the TTL
// values of the records.
func isCacheable(msg *dns.Msg) (ok bool) {
	if msg.Truncated || len(msg.Question) != 1 {
		return false
	}

	switch msg.Rcode {
	case dns.RcodeSuccess:
		return isCacheableNOERROR(msg)
	case
		dns.RcodeNameError,
		dns.RcodeServerFailure:
		return true
	default:
		return false
	}
}

// isCacheableNOERROR returns true if resp is a cacheable.  resp should be
// a NOERROR response.  resp is considered cacheable if either of the following
// is true:
//
//   - it's a response to a request with the corresponding records present in
//     the answer section; or
//
//   - it's a valid NODATA response to an A or AAAA request with an SOA record
//     in the authority section.
//
// TODO(a.garipov): Consider unifying with findLowestTTL.  It would be nice to
// be able to extract all relevant information about the cacheability of
// a response with one iteration.
func isCacheableNOERROR(resp *dns.Msg) (ok bool) {
	// Iterate through the answer section to find relevant records.  Skip CNAME
	// and SIG records, because a NODATA response may have either no records in
	// the answer section at all or have only these types.  Any other type of
	// record means that this is neither a real response nor a NODATA response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc2308#section-2.2.
	qt := resp.Question[0].Qtype
	for _, rr := range resp.Answer {
		rrType := rr.Header().Rrtype
		switch rrType {
		case qt:
			// This is a normal response to a question.  Cache it.
			return true
		case dns.TypeCNAME, dns.TypeSIG:
			// This could still be a NODATA response.  Go on.
		default:
			// This is a weird, non-NODATA response.  Don't cache it.
			return false
		}
	}

	// Find the SOA record in the authority section if there is one.  If there
	// isn't, this is not a cacheable NODATA response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc2308#section-5.
	for _, rr := range resp.Ns {
		if _, ok = rr.(*dns.SOA); ok {
			return true
		}
	}

	return false
}

// ServFailMaxCacheTTL is the maximum time-to-live value for caching
// SERVFAIL responses in seconds.  It's consistent with the upper constraint
// of 5 minutes given by RFC 2308.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
const ServFailMaxCacheTTL = 30

// findLowestTTL gets the lowest TTL among all DNS message's RRs.
func findLowestTTL(msg *dns.Msg) (ttl uint32) {
	// Use the maximum value as a guard value.  If the inner loop is entered,
	// it's going to be rewritten with an actual TTL value that is lower than
	// MaxUint32.  If the inner loop isn't entered, catch that and return zero.
	ttl = math.MaxUint32
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			ttl = getTTLIfLower(rr, ttl)
			if ttl == 0 {
				return 0
			}
		}
	}

	switch {
	case msg.Rcode == dns.RcodeServerFailure && ttl > ServFailMaxCacheTTL:
		return ServFailMaxCacheTTL
	case ttl == math.MaxUint32:
		return 0
	default:
		return ttl
	}
}

// getTTLIfLower is a helper function that checks the TTL of the specified RR
// and returns it if it's lower than the one passed in the arguments.
func getTTLIfLower(r dns.RR, ttl uint32) (res uint32) {
	switch r := r.(type) {
	case *dns.OPT:
		// Don't even consider the OPT RRs TTL.
		return ttl
	case *dns.SOA:
		if r.Minttl > 0 && r.Minttl < ttl {
			// Per RFC 2308, the TTL of a SOA RR is the minimum of SOA.MINIMUM
			// field and the header's value.
			ttl = r.Minttl
		}
	default:
		// Go on.
	}

	if httl := r.Header().Ttl; httl < ttl {
		return httl
	}

	return ttl
}
