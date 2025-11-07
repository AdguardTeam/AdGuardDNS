package dnsservertest

import (
	"net"
	"net/netip"
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

// NewA constructs the new resource record of type A.  a must be a valid 4-byte
// IPv4-address.
func NewA(name string, ttl uint32, a netip.Addr) (rr dns.RR) {
	data := a.As4()

	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: data[:],
	}
}

// NewAAAA constructs the new resource record of type AAAA.  aaaa must be a
// valid 16-byte IPv6-address.
func NewAAAA(name string, ttl uint32, aaaa netip.Addr) (rr dns.RR) {
	data := aaaa.As16()

	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		AAAA: data[:],
	}
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

// NewHTTPS constructs the new resource record of type HTTPS with IPv4 and IPv6
// hint records from provided v4Hint and v6Hint parameters.
//
// TODO(d.kolyshev): Add "alpn" and other SVCB key-value pairs.
func NewHTTPS(name string, ttl uint32, v4Hints, v6Hints []netip.Addr) (rr dns.RR) {
	v4Hint := &dns.SVCBIPv4Hint{}
	for _, ip := range v4Hints {
		v4Hint.Hint = append(v4Hint.Hint, ip.AsSlice())
	}
	v6Hint := &dns.SVCBIPv6Hint{}
	for _, ip := range v6Hints {
		v6Hint.Hint = append(v6Hint.Hint, ip.AsSlice())
	}

	svcb := dns.SVCB{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeHTTPS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Target: dns.Fqdn(name),
		Value:  []dns.SVCBKeyValue{v4Hint, v6Hint},
	}

	return &dns.HTTPS{
		SVCB: svcb,
	}
}

// NewPTR constructs the new resource record of type PTR.
func NewPTR(name string, ttl uint32, target string) (rr dns.RR) {
	return &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: dns.Fqdn(target),
	}
}

// NewSRV constructs the new resource record of type SRV.
func NewSRV(name string, ttl uint32, target string, prio, weight, port uint16) (rr dns.RR) {
	return &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Priority: prio,
		Weight:   weight,
		Port:     port,
		Target:   target,
	}
}

// NewSVCB constructs the new resource record of type SVCB.
func NewSVCB(
	name string,
	ttl uint32,
	target string,
	prio uint16,
	values ...dns.SVCBKeyValue,
) (rr dns.RR) {
	return &dns.SVCB{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeSVCB,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Priority: prio,
		Target:   target,
		Value:    values,
	}
}

// NewTXT constructs the new resource record of type TXT.  txts are put into the
// TXT record as is.
func NewTXT(name string, ttl uint32, txts ...string) (rr dns.RR) {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Txt: txts,
	}
}

// NewMX constructs the new resource record of type MX.
func NewMX(name string, ttl uint32, preference uint16, mx string) (rr dns.RR) {
	return &dns.MX{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Preference: preference,
		Mx:         mx,
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

// NewOPT constructs the new resource record of type OPT.
func NewOPT(do bool, udpSize uint16, opts ...dns.EDNS0) (rr dns.RR) {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: opts,
	}

	opt.SetDo(do)
	opt.SetUDPSize(udpSize)

	return opt
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
	if bufSzInt := int(UDPBufferSize); msgLen+padLen > bufSzInt {
		padLen = max(bufSzInt-msgLen, 0)
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
