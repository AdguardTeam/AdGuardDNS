// Package dnsmsg contains common constants, functions, and types for
// inspecting and constructing DNS messages.
//
// TODO(a.garipov): Consider moving all or some of this stuff to module golibs.
package dnsmsg

import (
	"fmt"
	"math"
	"net/netip"

	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Common Constants, Types, And Utilities

// RCode is a semantic alias for uint8 values when they are used as a DNS
// response code RCODE.
type RCode = uint8

// RRType is a semantic alias for uint16 values when they are used as a DNS
// resource record (RR) type.
type RRType = uint16

// Class is a semantic alias for uint16 values when they are used as a DNS class
// code.
type Class = uint16

// DefaultEDNSUDPSize is the default size used for EDNS content.
//
// See https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5.
const DefaultEDNSUDPSize = 4096

// MaxTXTStringLen is the maximum length of a single string within a TXT
// resource record.
//
// See also https://datatracker.ietf.org/doc/html/rfc6763#section-6.1.
const MaxTXTStringLen int = 255

// Clone returns a new *Msg which is a deep copy of msg.  Use this instead of
// msg.Copy, because the latter does not actually produce a deep copy of msg.
//
// See https://github.com/miekg/dns/issues/1351.
//
// TODO(a.garipov): See if we can also decrease allocations for such cases by
// modifying more of the original code.
func Clone(msg *dns.Msg) (clone *dns.Msg) {
	if msg == nil {
		return nil
	}

	// Don't just call clone.Copy to save call-stack space.
	clone = &dns.Msg{}
	msg.CopyTo(clone)

	// Make sure that nilness of the RR slices is retained.
	if msg.Answer == nil {
		clone.Answer = nil
	}

	if msg.Ns == nil {
		clone.Ns = nil
	}

	if msg.Extra == nil {
		clone.Extra = nil
	}

	return clone
}

// IsDO returns true if msg has an EDNS option pseudosection and that
// pseudosection has the DNSSEC OK (DO) bit set.
func IsDO(msg *dns.Msg) (ok bool) {
	opt := msg.IsEdns0()

	return opt != nil && opt.Do()
}

// ECSFromMsg returns the EDNS Client Subnet option information from msg, if
// any.  If there is none, it returns netip.Prefix{}.  msg must not be nil.  err
// is not nil only if msg contains a malformed EDNS Client Subnet option or the
// address family is unsupported (that is, neither IPv4 nor IPv6).  Any error
// returned from ECSFromMsg will have the underlying type of BadECSError.
func ECSFromMsg(msg *dns.Msg) (subnet netip.Prefix, scope uint8, err error) {
	opt := msg.IsEdns0()
	if opt == nil {
		return netip.Prefix{}, 0, nil
	}

	for _, opt := range opt.Option {
		esn, ok := opt.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}

		subnet, scope, err = ecsData(esn)
		if err != nil {
			return netip.Prefix{}, 0, BadECSError{Err: err}
		} else if subnet != (netip.Prefix{}) {
			return subnet, scope, nil
		}
	}

	return netip.Prefix{}, 0, nil
}

// ecsData returns the subnet and scope information from an EDNS Client Subnet
// option.  It returns an error if esn does not contain valid, RFC-compliant
// EDNS Client Subnet information or the address family is unsupported.
func ecsData(esn *dns.EDNS0_SUBNET) (subnet netip.Prefix, scope uint8, err error) {
	fam := netutil.AddrFamily(esn.Family)
	if fam != netutil.AddrFamilyIPv4 && fam != netutil.AddrFamilyIPv6 {
		return netip.Prefix{}, 0, fmt.Errorf("unsupported addr family number %d", fam)
	}

	ip, err := netutil.IPToAddr(esn.Address, fam)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("bad ecs ip addr: %w", err)
	}

	prefixLen := int(esn.SourceNetmask)
	subnet = netip.PrefixFrom(ip, prefixLen)
	if !subnet.IsValid() {
		return netip.Prefix{}, 0, fmt.Errorf(
			"bad src netmask %d for addr family %s",
			prefixLen,
			fam,
		)
	}

	// Make sure that the subnet address does not have any bits beyond the given
	// prefix set to one.
	//
	// See https://datatracker.ietf.org/doc/html/rfc7871#section-6.
	if subnet.Masked() != subnet {
		return netip.Prefix{}, 0, fmt.Errorf(
			"ip %s has non-zero bits beyond prefix %d",
			ip,
			prefixLen,
		)
	}

	return subnet, esn.SourceScope, nil
}

// SetMinTTL overrides TTL values of all answer records according to the min
// TTL.
func SetMinTTL(r *dns.Msg, minTTL uint32) {
	for _, rr := range r.Answer {
		h := rr.Header()

		// TODO(d.kolyshev): Use built-in max in go 1.21.
		h.Ttl = mathutil.Max(h.Ttl, minTTL)
	}
}

// ServFailMaxCacheTTL is the maximum time-to-live value for caching
// SERVFAIL responses in seconds.  It's consistent with the upper constraint
// of 5 minutes given by RFC 2308.
//
// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
const ServFailMaxCacheTTL = 30

// FindLowestTTL gets the lowest TTL among all DNS message's RRs.
func FindLowestTTL(msg *dns.Msg) (ttl uint32) {
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

	return mathutil.Min(r.Header().Ttl, ttl)
}
