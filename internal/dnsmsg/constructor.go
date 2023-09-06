package dnsmsg

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// DNS Message Constructor

// Constructor creates DNS messages for blocked or modified responses.
type Constructor struct {
	blockingMode BlockingMode
	fltRespTTL   time.Duration
}

// NewConstructor returns a properly initialized constructor with the given
// options.  respTTL is the time-to-live value used for responses created by
// this message constructor.  bm is the blocking mode to use in
// [Constructor.NewBlockedRespMsg].
func NewConstructor(bm BlockingMode, respTTL time.Duration) (c *Constructor) {
	return &Constructor{
		blockingMode: bm,
		fltRespTTL:   respTTL,
	}
}

// NewBlockedRespMsg returns a blocked DNS response message based on the
// constructor's blocking mode.
func (c *Constructor) NewBlockedRespMsg(req *dns.Msg) (msg *dns.Msg, err error) {
	switch m := c.blockingMode.(type) {
	case *BlockingModeCustomIP:
		return c.newBlockedCustomIPRespMsg(req, m)
	case *BlockingModeNullIP:
		switch qt := req.Question[0].Qtype; qt {
		case dns.TypeA, dns.TypeAAAA:
			return c.NewIPRespMsg(req, netip.Addr{})
		default:
			return c.NewMsgNODATA(req), nil
		}
	case *BlockingModeNXDOMAIN:
		return c.NewMsgNXDOMAIN(req), nil
	case *BlockingModeREFUSED:
		return c.NewMsgREFUSED(req), nil
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(fmt.Errorf("unexpected type %T", c.blockingMode))
	}
}

// newBlockedCustomIPRespMsg returns a blocked DNS response message with either
// the custom IPs from the blocking mode options or a NODATA one.
func (c *Constructor) newBlockedCustomIPRespMsg(
	req *dns.Msg,
	m *BlockingModeCustomIP,
) (msg *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		if m.IPv4.IsValid() {
			return c.NewIPRespMsg(req, m.IPv4)
		}
	case dns.TypeAAAA:
		if m.IPv6.IsValid() {
			return c.NewIPRespMsg(req, m.IPv6)
		}
	default:
		// Go on.
	}

	return c.NewMsgNODATA(req), nil
}

// NewIPRespMsg returns a DNS A or AAAA response message with the given IP
// addresses.  If any IP address is nil, it is replaced by an unspecified (aka
// null) IP.  The TTL is also set to c.FilteredResponseTTL.
func (c *Constructor) NewIPRespMsg(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		return c.newMsgA(req, ips...)
	case dns.TypeAAAA:
		return c.newMsgAAAA(req, ips...)
	default:
		return nil, fmt.Errorf("bad qtype for a or aaaa resp: %d", qt)
	}
}

// NewMsgFORMERR returns a properly initialized FORMERR response.
func (c *Constructor) NewMsgFORMERR(req *dns.Msg) (resp *dns.Msg) {
	return c.newMsgRCode(req, dns.RcodeFormatError)
}

// NewMsgNXDOMAIN returns a properly initialized NXDOMAIN response.
func (c *Constructor) NewMsgNXDOMAIN(req *dns.Msg) (resp *dns.Msg) {
	return c.newMsgRCode(req, dns.RcodeNameError)
}

// NewMsgREFUSED returns a properly initialized REFUSED response.
func (c *Constructor) NewMsgREFUSED(req *dns.Msg) (resp *dns.Msg) {
	return c.newMsgRCode(req, dns.RcodeRefused)
}

// NewMsgSERVFAIL returns a properly initialized SERVFAIL response.
func (c *Constructor) NewMsgSERVFAIL(req *dns.Msg) (resp *dns.Msg) {
	return c.newMsgRCode(req, dns.RcodeServerFailure)
}

// NewMsgNODATA returns a properly initialized NODATA response.
//
// See https://www.rfc-editor.org/rfc/rfc2308#section-2.2.
func (c *Constructor) NewMsgNODATA(req *dns.Msg) (resp *dns.Msg) {
	return c.newMsgRCode(req, dns.RcodeSuccess)
}

// newMsgRCode returns a properly initialized response with the given RCode.
func (c *Constructor) newMsgRCode(req *dns.Msg, rc RCode) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetRcode(req, int(rc))
	resp.Ns = c.newSOARecords(req)
	resp.RecursionAvailable = true

	return resp
}

// NewTXTRespMsg returns a DNS TXT response message with the given strings as
// content.  The TTL is also set to c.FilteredResponseTTL.
func (c *Constructor) NewTXTRespMsg(req *dns.Msg, strs ...string) (msg *dns.Msg, err error) {
	ans, err := c.NewAnsTXT(req, strs)
	if err != nil {
		return nil, err
	}

	msg = c.NewRespMsg(req)
	msg.Answer = append(msg.Answer, ans)

	return msg, nil
}

// AppendDebugExtra appends to response message a DNS TXT extra with CHAOS
// class.
func (c *Constructor) AppendDebugExtra(req, resp *dns.Msg, str string) (err error) {
	qt := req.Question[0].Qtype
	if qt != dns.TypeTXT {
		return fmt.Errorf("bad qtype for txt resp: %s", dns.Type(qt))
	}

	strLen := len(str)

	if strLen <= MaxTXTStringLen {
		resp.Extra = append(resp.Extra, &dns.TXT{
			Hdr: c.newHdrWithClass(req, dns.TypeTXT, dns.ClassCHAOS),
			Txt: []string{str},
		})

		return nil
	}

	// Integer division truncates towards zero, which means flooring for
	// positive numbers, but we need a ceiling operation here.
	strNum := (strLen + MaxTXTStringLen - 1) / MaxTXTStringLen

	newStr := make([]string, strNum)
	for i := 0; i < strNum; i++ {
		start := i * MaxTXTStringLen

		var cutStr string
		if i == strNum-1 {
			cutStr = str[start:]
		} else {
			cutStr = str[start : start+MaxTXTStringLen]
		}

		newStr[i] = cutStr
	}

	resp.Extra = append(resp.Extra, &dns.TXT{
		Hdr: c.newHdrWithClass(req, dns.TypeTXT, dns.ClassCHAOS),
		Txt: newStr,
	})

	return nil
}

// newHdr returns a new resource record header.
func (c *Constructor) newHdr(req *dns.Msg, rrType RRType) (hdr dns.RR_Header) {
	return dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: rrType,
		Ttl:    uint32(c.fltRespTTL.Seconds()),
		Class:  dns.ClassINET,
	}
}

// newHdrWithClass returns a new resource record header with specified class.
func (c *Constructor) newHdrWithClass(req *dns.Msg, rrType RRType, cl dns.Class) (h dns.RR_Header) {
	return dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: rrType,
		Ttl:    uint32(c.fltRespTTL.Seconds()),
		Class:  uint16(cl),
	}
}

// NewAnsA returns a new resource record with an IPv4 address.  ip must be an
// IPv4 address.  If ip is a zero netip.Addr, it is replaced by an unspecified
// (aka null) IP, 0.0.0.0.
func (c *Constructor) NewAnsA(req *dns.Msg, ip netip.Addr) (ans *dns.A, err error) {
	if ip == (netip.Addr{}) {
		ip = netip.IPv4Unspecified()
	} else if !ip.Is4() {
		return nil, fmt.Errorf("bad ipv4: %s", ip)
	}

	data := ip.As4()

	return &dns.A{
		Hdr: c.newHdr(req, dns.TypeA),
		A:   data[:],
	}, nil
}

// NewAnsAAAA returns a new resource record with an IPv6 address.  ip must be an
// IPv6 address.  If ip is a zero netip.Addr, it is replaced by an unspecified
// (aka null) IP, [::].
func (c *Constructor) NewAnsAAAA(req *dns.Msg, ip netip.Addr) (ans *dns.AAAA, err error) {
	if ip == (netip.Addr{}) {
		ip = netip.IPv6Unspecified()
	} else if !ip.Is6() {
		return nil, fmt.Errorf("bad ipv6: %s", ip)
	}

	data := ip.As16()

	return &dns.AAAA{
		Hdr:  c.newHdr(req, dns.TypeAAAA),
		AAAA: data[:],
	}, nil
}

// NewAnsTXT returns a new resource record of TXT type.
func (c *Constructor) NewAnsTXT(req *dns.Msg, strs []string) (ans *dns.TXT, err error) {
	qt := req.Question[0].Qtype
	if qt != dns.TypeTXT {
		return nil, fmt.Errorf("bad qtype for txt resp: %s", dns.Type(qt))
	}

	for i, s := range strs {
		if l := len(s); l > MaxTXTStringLen {
			// TODO(a.garipov): Use agd.ValidateInclusion if it moves from
			// package agd into golibs.
			return nil, fmt.Errorf(
				"txt string at index %d: too long: got %d bytes, max %d",
				i,
				l,
				MaxTXTStringLen,
			)
		}
	}

	return &dns.TXT{
		Hdr: c.newHdr(req, dns.TypeTXT),
		Txt: strs,
	}, nil
}

// NewAnsPTR returns a new resource record of PTR type.
func (c *Constructor) NewAnsPTR(req *dns.Msg, ptr string) (ans *dns.PTR) {
	return &dns.PTR{
		Hdr: c.newHdr(req, dns.TypePTR),
		Ptr: dns.Fqdn(ptr),
	}
}

// NewAnswerMX returns a new resource record of MX type.
func (c *Constructor) NewAnswerMX(req *dns.Msg, mx *rules.DNSMX) (ans *dns.MX) {
	return &dns.MX{
		Hdr:        c.newHdr(req, dns.TypeMX),
		Preference: mx.Preference,
		Mx:         dns.Fqdn(mx.Exchange),
	}
}

// NewAnswerSRV returns a new resource record of SRV type.
func (c *Constructor) NewAnswerSRV(req *dns.Msg, srv *rules.DNSSRV) (ans *dns.SRV) {
	return &dns.SRV{
		Hdr:      c.newHdr(req, dns.TypeSRV),
		Priority: srv.Priority,
		Weight:   srv.Weight,
		Port:     srv.Port,
		Target:   dns.Fqdn(srv.Target),
	}
}

// NewAnswerCNAME returns a new resource record of CNAME type.
func (c *Constructor) NewAnswerCNAME(req *dns.Msg, cname string) (ans *dns.CNAME) {
	return &dns.CNAME{
		Hdr:    c.newHdr(req, dns.TypeCNAME),
		Target: dns.Fqdn(cname),
	}
}

// newSOARecords generates the Start Of Authority record for AdGuardDNS.  It
// must be used with all blocked responses.
func (c *Constructor) newSOARecords(req *dns.Msg) (soaRecs []dns.RR) {
	zone := ""
	if len(req.Question) > 0 {
		zone = req.Question[0].Name
	}

	// TODO(a.garipov): A lot of this is copied from AdGuard Home and needs
	// to be inspected and refactored.
	soa := &dns.SOA{
		// values copied from verisign's nonexistent .com domain
		// their exact values are not important in our use case because they are used for domain transfers between primary/secondary DNS servers
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  86400,
		// copied from AdGuard DNS
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		// rest is request-specific
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Ttl:    uint32(c.fltRespTTL.Seconds()),
			Class:  dns.ClassINET,
		},
		Mbox: "hostmaster.", // zone will be appended later if it's not empty or "."
	}

	if len(zone) > 0 && zone[0] != '.' {
		soa.Mbox += zone
	}

	return []dns.RR{soa}
}

// NewRespMsg creates a DNS response for req and sets all necessary flags and
// fields.  It also guarantees that req.Question will be not empty.
func (c *Constructor) NewRespMsg(req *dns.Msg) (resp *dns.Msg) {
	resp = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionAvailable: true,
		},
		Compress: true,
	}

	resp.SetReply(req)

	return resp
}

// newMsgA returns a new DNS response with the given IPv4 addresses.  If any IP
// address is nil, it is replaced by an unspecified (aka null) IP, 0.0.0.0.
func (c *Constructor) newMsgA(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	msg = c.NewRespMsg(req)
	for i, ip := range ips {
		var ans dns.RR
		ans, err = c.NewAnsA(req, ip)
		if err != nil {
			return nil, fmt.Errorf("bad ip at idx %d: %w", i, err)
		}

		msg.Answer = append(msg.Answer, ans)
	}

	return msg, nil
}

// newMsgAAAA returns a new DNS response with the given IPv6 addresses.  If any
// IP address is nil, it is replaced by an unspecified (aka null) IP, [::].
func (c *Constructor) newMsgAAAA(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	msg = c.NewRespMsg(req)
	for i, ip := range ips {
		var ans dns.RR
		ans, err = c.NewAnsAAAA(req, ip)
		if err != nil {
			return nil, fmt.Errorf("bad ip at idx %d: %w", i, err)
		}

		msg.Answer = append(msg.Answer, ans)
	}

	return msg, nil
}
