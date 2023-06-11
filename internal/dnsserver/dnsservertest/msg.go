package dnsservertest

import (
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// CreateMessage creates a DNS message for the specified hostname and qtype.
func CreateMessage(hostname string, qtype uint16) (m *dns.Msg) {
	m = NewReq(hostname, qtype, dns.ClassINET)
	m.RecursionDesired = true

	return m
}

// RequireResponse checks that the DNS response we received is what was
// expected.
func RequireResponse(
	t *testing.T,
	req *dns.Msg,
	resp *dns.Msg,
	wantAnsLen int,
	wantRCode int,
	wantTruncated bool,
) {
	t.Helper()

	require.NotNil(t, req)
	require.NotNil(t, resp)
	// Check that Opcode is not changed in the response
	// regardless of the response status
	require.Equal(t, req.Opcode, resp.Opcode)
	require.Equal(t, wantRCode, resp.Rcode)
	require.Equal(t, wantTruncated, resp.Truncated)
	require.True(t, resp.Response)
	// Response must not have a Z flag set even for a query that does
	// See https://github.com/miekg/dns/issues/975
	require.False(t, resp.Zero)
	require.Len(t, resp.Answer, wantAnsLen)

	// Check that there's an OPT record in the response
	if len(req.Extra) > 0 {
		require.NotEmpty(t, resp.Extra)
	}

	if wantAnsLen > 0 {
		a := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0])
		require.Equal(t, req.Question[0].Name, a.Hdr.Name)
	}
}

// RRSection is the resource record set to be appended to a new message created
// by [NewReq] and [NewResp].  It's essentially a sum type of:
//
//   - [SectionAnswer]
//   - [SectionNs]
//   - [SectionExtra]
type RRSection interface {
	// appendTo modifies m adding the resource record set into it appropriately.
	appendTo(m *dns.Msg)
}

// type check
var (
	_ RRSection = SectionAnswer{}
	_ RRSection = SectionNs{}
	_ RRSection = SectionExtra{}
)

// SectionAnswer should wrap a resource record set for the Answer section of DNS
// message.
type SectionAnswer []dns.RR

// appendTo implements the [RRSection] interface for SectionAnswer.
func (rrs SectionAnswer) appendTo(m *dns.Msg) { m.Answer = append(m.Answer, ([]dns.RR)(rrs)...) }

// SectionNs should wrap a resource record set for the Ns section of DNS
// message.
type SectionNs []dns.RR

// appendTo implements the [RRSection] interface for SectionNs.
func (rrs SectionNs) appendTo(m *dns.Msg) { m.Ns = append(m.Ns, ([]dns.RR)(rrs)...) }

// SectionExtra should wrap a resource record set for the Extra section of DNS
// message.
type SectionExtra []dns.RR

// appendTo implements the [RRSection] interface for SectionExtra.
func (rrs SectionExtra) appendTo(m *dns.Msg) { m.Extra = append(m.Extra, ([]dns.RR)(rrs)...) }

// NewReq returns the new DNS request with a single question for name, qtype,
// qclass, and rrs added.
func NewReq(name string, qtype, qclass uint16, rrs ...RRSection) (req *dns.Msg) {
	req = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(name),
			Qtype:  qtype,
			Qclass: qclass,
		}},
	}

	for _, rr := range rrs {
		rr.appendTo(req)
	}

	return req
}

// NewResp returns the new DNS response with response code set to rcode, req
// used as request, and rrs added.
func NewResp(rcode int, req *dns.Msg, rrs ...RRSection) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, rcode)
	resp.RecursionAvailable = true
	resp.Compress = true

	for _, rr := range rrs {
		rr.appendTo(resp)
	}

	return resp
}

// NewCNAME constructs the new resource record of type CNAME.
func NewCNAME(name string, ttl uint32, target string) (rr dns.RR) {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Target: dns.Fqdn(target),
	}
}

// NewA constructs the new resource record of type A.  a must be a valid 4-byte
// IPv4-address.
func NewA(name string, ttl uint32, a net.IP) (rr dns.RR) {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: a,
	}
}

// NewAAAA constructs the new resource record of type AAAA.  aaaa must be a
// valid 16-byte IPv6-address.
func NewAAAA(name string, ttl uint32, aaaa net.IP) (rr dns.RR) {
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		AAAA: aaaa,
	}
}

// NewSOA constructs the new resource record of type SOA.
func NewSOA(name string, ttl uint32, ns, mbox string) (rr dns.RR) {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:   dns.Fqdn(ns),
		Mbox: dns.Fqdn(mbox),
	}
}

// NewNS constructs the new resource record of type NS.
func NewNS(name string, ttl uint32, ns string) (rr dns.RR) {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns: dns.Fqdn(ns),
	}
}

// NewECSExtra constructs a new OPT RR for the extra section.
func NewECSExtra(ip net.IP, fam uint16, mask, scope uint8) (extra dns.RR) {
	return &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: []dns.EDNS0{&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        fam,
			SourceNetmask: mask,
			SourceScope:   scope,
			Address:       ip,
		}},
	}
}

// requestPaddingBlockSize is used to pad responses over DoT and DoH according
// to RFC 8467.
const requestPaddingBlockSize = 128

// NewEDNS0Padding constructs a new OPT RR EDNS0 Padding for the extra section
// in queries according to RFC 8467.
func NewEDNS0Padding(msgLen int, UDPBufferSize uint16) (extra dns.RR) {
	padLen := requestPaddingBlockSize - msgLen%requestPaddingBlockSize

	// Truncate padding to fit in UDP buffer.
	if msgLen+padLen > int(UDPBufferSize) {
		padLen = int(UDPBufferSize) - msgLen
		if padLen < 0 {
			padLen = 0
		}
	}

	return &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: UDPBufferSize},
		Option: []dns.EDNS0{
			&dns.EDNS0_PADDING{Padding: make([]byte, padLen)},
		},
	}
}

// FindEDNS0Option searches for the specified EDNS0 option in the OPT resource
// record of the msg and returns it or nil if it's not present.
func FindEDNS0Option[T dns.EDNS0](msg *dns.Msg) (o T) {
	rr := msg.IsEdns0()
	if rr == nil {
		return o
	}

	for _, opt := range rr.Option {
		var ok bool
		if o, ok = opt.(T); ok {
			return o
		}
	}

	return o
}
