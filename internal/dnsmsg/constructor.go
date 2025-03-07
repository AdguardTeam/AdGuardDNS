package dnsmsg

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// ConstructorConfig is a configuration for the constructor of DNS messages.
type ConstructorConfig struct {
	// Cloner used to clone DNS messages.  It must not be nil.
	Cloner *Cloner

	// StructuredErrors is the configuration for the experimental Structured DNS
	// Errors feature.  It must not be nil.  If enabled,
	// [ConstructorConfig.EDEEnabled] should also be true.
	StructuredErrors *StructuredDNSErrorsConfig

	// BlockingMode is the blocking mode to use in [Constructor.NewBlockedResp].
	// It must not be nil.
	BlockingMode BlockingMode

	// FilteredResponseTTL is the time-to-live value used for responses created
	// by this message constructor.  It must be non-negative.
	FilteredResponseTTL time.Duration

	// EDEEnabled enables the addition of the Extended DNS Error (EDE) codes.
	EDEEnabled bool
}

// validate checks the configuration for errors.
func (conf *ConstructorConfig) validate() (err error) {
	var errs []error

	if conf.Cloner == nil {
		err = fmt.Errorf("cloner: %w", errors.ErrNoValue)
		errs = append(errs, err)
	}

	err = conf.StructuredErrors.validate(conf.EDEEnabled)
	if err != nil {
		err = fmt.Errorf("structured errors: %w", err)
		errs = append(errs, err)
	}

	if conf.BlockingMode == nil {
		err = fmt.Errorf("blocking mode: %w", errors.ErrNoValue)
		errs = append(errs, err)
	}

	if conf.FilteredResponseTTL < 0 {
		err = fmt.Errorf("filtered response ttl: %w", errors.ErrNegative)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// Constructor creates DNS messages for blocked or modified responses.  It must
// be created using [NewConstructor].
type Constructor struct {
	cloner       *Cloner
	blockingMode BlockingMode
	sde          string
	fltRespTTL   time.Duration
	edeEnabled   bool
}

// NewConstructor returns a properly initialized constructor using conf.
func NewConstructor(conf *ConstructorConfig) (c *Constructor, err error) {
	if err = conf.validate(); err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}

	var sde string
	if sdeConf := conf.StructuredErrors; sdeConf.Enabled {
		sde = sdeConf.iJSON()
	}

	return &Constructor{
		cloner:       conf.Cloner,
		blockingMode: conf.BlockingMode,
		sde:          sde,
		fltRespTTL:   conf.FilteredResponseTTL,
		edeEnabled:   conf.EDEEnabled,
	}, nil
}

// Cloner returns the constructor's Cloner.
func (c *Constructor) Cloner() (cloner *Cloner) {
	return c.cloner
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
			Hdr: c.newHdrWithClass(req.Question[0].Name, dns.TypeTXT, dns.ClassCHAOS),
			Txt: []string{str},
		})

		return nil
	}

	// Integer division truncates towards zero, which means flooring for
	// positive numbers, but we need a ceiling operation here.
	strNum := (strLen + MaxTXTStringLen - 1) / MaxTXTStringLen

	// TODO(a.garipov): Consider adding strings.Chunks to golibs.
	newStr := make([]string, strNum)
	for i := range strNum {
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
		Hdr: c.newHdrWithClass(req.Question[0].Name, dns.TypeTXT, dns.ClassCHAOS),
		Txt: newStr,
	})

	return nil
}

// newHdr returns a new resource record header.
func (c *Constructor) newHdr(req *dns.Msg, rrType RRType) (hdr dns.RR_Header) {
	return c.newHdrWithClass(req.Question[0].Name, rrType, dns.ClassINET)
}

// newHdrWithClass returns a new resource record header with specified class.
// fqdn is the fully-qualified name and must not be empty.
func (c *Constructor) newHdrWithClass(fqdn string, rrType RRType, cl dns.Class) (h dns.RR_Header) {
	return dns.RR_Header{
		Name:   fqdn,
		Rrtype: rrType,
		Ttl:    uint32(c.fltRespTTL.Seconds()),
		Class:  uint16(cl),
	}
}

// NewAnswerA returns a new resource record with the given IPv4 address and
// fqdn.  fqdn is the fully-qualified name and must not be empty.  ip must be
// an IPv4 address.  If ip is a zero netip.Addr, it is replaced by an
// unspecified (aka null) IP, 0.0.0.0.
//
// TODO(a.garipov): Use FQDN in all other answer constructors.
func (c *Constructor) NewAnswerA(fqdn string, ip netip.Addr) (rr *dns.A, err error) {
	if ip == (netip.Addr{}) {
		ip = netip.IPv4Unspecified()
	} else if !ip.Is4() {
		return nil, fmt.Errorf("bad ipv4: %s", ip)
	}

	rr = newA(c.cloner, ip)
	rr.Hdr = c.newHdrWithClass(fqdn, dns.TypeA, dns.ClassINET)

	return rr, nil
}

// NewAnswerAAAA returns a new resource record with the given IPv6 address and
// fqdn.  fqdn is the fully-qualified name and must not be empty.  ip must be an
// IPv6 address.  If ip is a zero netip.Addr, it is replaced by an unspecified
// (aka null) IP, [::].
func (c *Constructor) NewAnswerAAAA(fqdn string, ip netip.Addr) (rr *dns.AAAA, err error) {
	if ip == (netip.Addr{}) {
		ip = netip.IPv6Unspecified()
	} else if !ip.Is6() {
		return nil, fmt.Errorf("bad ipv6: %s", ip)
	}

	rr = newAAAA(c.cloner, ip)
	rr.Hdr = c.newHdrWithClass(fqdn, dns.TypeAAAA, dns.ClassINET)

	return rr, nil
}

// NewAnswerCNAME returns a new resource record of CNAME type.
func (c *Constructor) NewAnswerCNAME(req *dns.Msg, target string) (rr *dns.CNAME) {
	rr = newCNAME(c.cloner, dns.Fqdn(target))
	rr.Hdr = c.newHdr(req, dns.TypeCNAME)

	return rr
}

// NewAnswerMX returns a new resource record of MX type.
func (c *Constructor) NewAnswerMX(req *dns.Msg, mx *rules.DNSMX) (rr *dns.MX) {
	rr = newMX(c.cloner, dns.Fqdn(mx.Exchange), mx.Preference)
	rr.Hdr = c.newHdr(req, dns.TypeMX)

	return rr
}

// NewAnswerPTR returns a new resource record of PTR type.
func (c *Constructor) NewAnswerPTR(req *dns.Msg, ptr string) (rr *dns.PTR) {
	rr = newPTR(c.cloner, dns.Fqdn(ptr))
	rr.Hdr = c.newHdr(req, dns.TypePTR)

	return rr
}

// NewAnswerSRV returns a new resource record of SRV type.
func (c *Constructor) NewAnswerSRV(req *dns.Msg, srv *rules.DNSSRV) (rr *dns.SRV) {
	rr = newSRV(c.cloner, dns.Fqdn(srv.Target), srv.Priority, srv.Weight, srv.Port)
	rr.Hdr = c.newHdr(req, dns.TypeSRV)

	return rr
}

// NewAnswerTXT returns a new resource record of TXT type.
func (c *Constructor) NewAnswerTXT(req *dns.Msg, strs []string) (rr *dns.TXT, err error) {
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

	rr = newTXT(c.cloner, strs)
	rr.Hdr = c.newHdr(req, dns.TypeTXT)

	return rr, nil
}

// newSOARecords generates the Start Of Authority record for AdGuardDNS.  It
// must be used with all blocked responses.
func (c *Constructor) newSOARecords(req *dns.Msg) (soaRecs []dns.RR) {
	zone := ""
	if len(req.Question) > 0 {
		zone = req.Question[0].Name
	}

	// TODO(a.garipov): A lot of this is copied from AdGuard Home and needs to
	// be inspected and refactored.
	soa := &dns.SOA{
		// Use values from verisign's nonexistent.com domain.  Their exact
		// values are not important in our use case because they are used for
		// domain transfers between primary/secondary DNS servers.
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  86400,
		// Copied from AdGuard DNS.
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		// Rest is request-specific.
		Hdr: c.newHdrWithClass(zone, dns.TypeSOA, dns.ClassINET),
		// Zone will be appended later if it's not empty or ".".
		Mbox: "hostmaster.",
	}

	if len(zone) > 0 && zone[0] != '.' {
		soa.Mbox += zone
	}

	return []dns.RR{soa}
}

// newMsgA returns a new DNS response with the given IPv4 addresses.  If any IP
// address is nil, it is replaced by an unspecified (aka null) IP, 0.0.0.0.
func (c *Constructor) newMsgA(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	msg = c.NewResp(req)
	for i, ip := range ips {
		var ans dns.RR
		ans, err = c.NewAnswerA(req.Question[0].Name, ip)
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
	msg = c.NewResp(req)
	for i, ip := range ips {
		var ans dns.RR
		ans, err = c.NewAnswerAAAA(req.Question[0].Name, ip)
		if err != nil {
			return nil, fmt.Errorf("bad ip at idx %d: %w", i, err)
		}

		msg.Answer = append(msg.Answer, ans)
	}

	return msg, nil
}
