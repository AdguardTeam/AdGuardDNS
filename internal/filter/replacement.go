package filter

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// ReplacedResultConstructor creates replaced results that are either
// [*ResultModifiedRequest]s or [*ResultModifiedResponse]s.
type ReplacedResultConstructor struct {
	cloner   *dnsmsg.Cloner
	replIP   netip.Addr
	replFQDN string
}

// ReplacedResultConstructorConfig is the configuration structure for a
// [ReplacedResultConstructor].
type ReplacedResultConstructorConfig struct {
	// Cloner is used to clone DNS messages for results.  It must not be nil.
	Cloner *dnsmsg.Cloner

	// Replacement is the replacement host or IP address for this constructor.
	// If Replacement contains a valid IP, that IP is used.  Otherwise, it
	// should be a valid domain name.
	Replacement string
}

// NewReplacedResultConstructor returns a new properly initialized
// *ReplacedResultConstructor.  c must be valid.
func NewReplacedResultConstructor(
	c *ReplacedResultConstructorConfig,
) (cons *ReplacedResultConstructor, err error) {
	cons = &ReplacedResultConstructor{
		cloner: c.Cloner,
	}

	if netutil.IsValidIPString(c.Replacement) {
		cons.replIP = netip.MustParseAddr(c.Replacement)
	} else {
		err = netutil.ValidateDomainName(c.Replacement)
		if err != nil {
			return nil, fmt.Errorf("replacement: %w", err)
		}

		cons.replFQDN = dns.Fqdn(c.Replacement)
	}

	return cons, nil
}

// New returns a filtered request or response using text as the rule text in the
// result.  req must not be nil.  fam must be valid.
func (c *ReplacedResultConstructor) New(
	req *Request,
	id ID,
	text RuleText,
	fam netutil.AddrFamily,
) (r Result, err error) {
	if c.replFQDN != "" {
		modReq := c.cloner.Clone(req.DNS)
		modReq.Question[0].Name = c.replFQDN

		return &ResultModifiedRequest{
			Msg:  modReq,
			List: id,
			Rule: text,
		}, nil
	}

	resp, err := c.respForFamily(req, fam)
	if err != nil {
		return nil, fmt.Errorf("filter %s: creating modified result: %w", id, err)
	}

	return &ResultModifiedResponse{
		Msg:  resp,
		List: id,
		Rule: text,
	}, nil
}

// respForFamily returns a filtered response in accordance with the protocol
// family and question type. req must not be nil.  fam must be valid.
func (c *ReplacedResultConstructor) respForFamily(
	req *Request,
	fam netutil.AddrFamily,
) (resp *dns.Msg, err error) {
	if fam == netutil.AddrFamilyNone {
		// This is an HTTPS query.  For them, just return NODATA or other
		// blocked response.  See AGDNS-1551.
		//
		// TODO(ameshkov): Consider putting the resolved IP addresses into hints
		// to show the blocked page here as well?
		return req.Messages.NewBlockedResp(req.DNS, nil)
	}

	ip := c.replIP

	switch {
	case ip.Is4() && fam == netutil.AddrFamilyIPv4:
		return req.Messages.NewBlockedRespIP(req.DNS, ip)
	case ip.Is6() && fam == netutil.AddrFamilyIPv6:
		return req.Messages.NewBlockedRespIP(req.DNS, ip)
	default:
		// TODO(e.burkov):  Use [dnsmsg.Constructor.NewBlockedRespRCode] when it
		// adds SOA records.
		resp = req.Messages.NewRespRCode(req.DNS, dns.RcodeSuccess)
		req.Messages.AddEDE(req.DNS, resp, dns.ExtendedErrorCodeFiltered)

		return resp, nil
	}
}
