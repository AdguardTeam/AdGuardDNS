package dnsservertest

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// CreateMessage creates a DNS message for the specified hostname and qtype.
func CreateMessage(hostname string, qtype uint16) (m *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(hostname),
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}
}

// RequireResponse checks that the DNS response we received is what was
// expected.
func RequireResponse(
	t *testing.T,
	req *dns.Msg,
	resp *dns.Msg,
	expectedRecordsCount int,
	expectedRCode int,
	expectedTruncated bool,
) {
	t.Helper()

	require.NotNil(t, req)
	require.NotNil(t, resp)
	// Check that Opcode is not changed in the response
	// regardless of the response status
	require.Equal(t, req.Opcode, resp.Opcode)
	require.Equal(t, expectedRCode, resp.Rcode)
	require.Equal(t, expectedTruncated, resp.Truncated)
	require.True(t, resp.Response)
	// Response must not have a Z flag set even for a query that does
	// See https://github.com/miekg/dns/issues/975
	require.False(t, resp.Zero)
	require.Equal(t, expectedRecordsCount, len(resp.Answer))

	// Check that there's an OPT record in the response
	if len(req.Extra) > 0 {
		require.True(t, len(resp.Extra) > 0)
	}

	if expectedRecordsCount > 0 {
		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		require.Equal(t, req.Question[0].Name, a.Hdr.Name)
	}
}

// NewReq returns the new DNS request with a single question for name, qtype,
// qclass, and rrs added.
func NewReq(name string, qtype, qclass uint16, rrs ...RRSection) (req *dns.Msg) {
	req = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Question: []dns.Question{{
			Name:   name,
			Qtype:  qtype,
			Qclass: qclass,
		}},
	}

	withRRs(req, rrs...)

	return req
}

// NewResp returns the new DNS response with response code set to rcode, req
// used as request, and rrs added.
func NewResp(rcode int, req *dns.Msg, rrs ...RRSection) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, rcode)
	resp.RecursionAvailable = true
	resp.Compress = true

	withRRs(resp, rrs...)

	return resp
}

// MsgSection is used to specify the resource record set of the DNS message.
type MsgSection int

// Possible values of the MsgSection.
const (
	SectionAnswer MsgSection = iota
	SectionNs
	SectionExtra
)

// RRSection is the slice of resource records to be appended to a new message
// created by NewReq and NewResp.
type RRSection struct {
	RRs []dns.RR
	Sec MsgSection
}

// withRRs adds rrs to the m.  Invalid rrs are skipped.
func withRRs(m *dns.Msg, rrs ...RRSection) {
	for _, r := range rrs {
		var msgRR *[]dns.RR
		switch r.Sec {
		case SectionAnswer:
			msgRR = &m.Answer
		case SectionNs:
			msgRR = &m.Ns
		case SectionExtra:
			msgRR = &m.Extra
		default:
			continue
		}

		*msgRR = append(*msgRR, r.RRs...)
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

// NewA constructs the new resource record of type A.
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

// FindENDS0Option searches for the specified EDNS0 option in the OPT resource
// record of the msg and returns it or nil if it's not present.
func FindENDS0Option[T dns.EDNS0](msg *dns.Msg) (o T) {
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
