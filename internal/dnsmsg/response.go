package dnsmsg

import (
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
)

// NewResp creates a response DNS message for req and sets all necessary flags
// and fields.  resp contains no resource records.
func (c *Constructor) NewResp(req *dns.Msg) (resp *dns.Msg) {
	return (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionAvailable: true,
		},
		Compress: true,
	}).SetReply(req)
}

// NewBlockedResp returns a blocked response DNS message based on the given
// blocking mode.  If mode is nil, the constructor's blocking mode is used.
func (c *Constructor) NewBlockedResp(req *dns.Msg, mode BlockingMode) (msg *dns.Msg, err error) {
	if mode == nil {
		mode = c.blockingMode
	}

	switch m := mode.(type) {
	case *BlockingModeCustomIP:
		return c.newBlockedCustomIPResp(req, m)
	case *BlockingModeNullIP:
		switch qt := req.Question[0].Qtype; qt {
		case dns.TypeA, dns.TypeAAAA:
			return c.NewBlockedNullIPResp(req)
		default:
			msg = c.NewBlockedRespRCode(req, dns.RcodeSuccess)
			msg.Ns = c.newSOARecords(req)
		}
	case *BlockingModeNXDOMAIN:
		msg = c.NewBlockedRespRCode(req, dns.RcodeNameError)
		msg.Ns = c.newSOARecords(req)
	case *BlockingModeREFUSED:
		msg = c.NewBlockedRespRCode(req, dns.RcodeRefused)
		msg.Ns = c.newSOARecords(req)
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(fmt.Errorf("unexpected type %T", c.blockingMode))
	}

	return msg, nil
}

// NewRespRCode returns a response DNS message with given response code and a
// predefined authority section.
//
// Use [dns.RcodeSuccess] for a proper NODATA response, see
// https://www.rfc-editor.org/rfc/rfc2308#section-2.2.
func (c *Constructor) NewRespRCode(req *dns.Msg, rc RCode) (resp *dns.Msg) {
	resp = c.NewResp(req)
	resp.Rcode = int(rc)

	resp.Ns = c.newSOARecords(req)

	return resp
}

// NewBlockedRespRCode returns a blocked response DNS message with given
// response code.
//
// TODO(e.burkov):  Add SOA records to the response, like in
// [Constructor.NewRespRCode].
func (c *Constructor) NewBlockedRespRCode(req *dns.Msg, rc RCode) (resp *dns.Msg) {
	resp = c.NewResp(req)
	resp.Rcode = int(rc)

	c.AddEDE(req, resp, dns.ExtendedErrorCodeFiltered)

	return resp
}

// NewRespTXT returns a DNS TXT response message with the given strings as
// content.  The TTL of the TXT answer is set to c.FilteredResponseTTL.
func (c *Constructor) NewRespTXT(req *dns.Msg, strs ...string) (msg *dns.Msg, err error) {
	ans, err := c.NewAnswerTXT(req, strs)
	if err != nil {
		return nil, err
	}

	msg = c.NewResp(req)
	msg.Answer = append(msg.Answer, ans)

	return msg, nil
}

// NewRespIP returns an A or AAAA DNS response message with the given IP
// addresses.  If any IP address is nil, it is replaced by an unspecified (aka
// null) IP.  The TTL is also set to c.FilteredResponseTTL.
func (c *Constructor) NewRespIP(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		return c.newMsgA(req, ips...)
	case dns.TypeAAAA:
		return c.newMsgAAAA(req, ips...)
	default:
		return nil, fmt.Errorf("bad qtype for a or aaaa resp: %d", qt)
	}
}

// NewBlockedRespIP returns an A or AAAA DNS response message with the given IP
// addresses.  The TTL of each record is set to c.FilteredResponseTTL.  ips
// should not contain zero values due to the extended error code semantics, use
// [NewBlockedNullIPResp] for this case.
//
// TODO(a.garipov):  Consider merging with [NewRespIP] if AddEDE with the Forged
// Answer code isn't used again.
func (c *Constructor) NewBlockedRespIP(req *dns.Msg, ips ...netip.Addr) (msg *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		msg, err = c.newMsgA(req, ips...)
	case dns.TypeAAAA:
		msg, err = c.newMsgAAAA(req, ips...)
	default:
		return nil, fmt.Errorf("bad qtype for an ip resp: %d", qt)
	}

	if err != nil {
		return nil, err
	}

	return msg, nil
}

// NewBlockedNullIPResp returns a blocked A or AAAA DNS response message with an
// unspecified (aka null) IP address.  The TTL of the record is set to the
// constructor's FilteredResponseTTL.
func (c *Constructor) NewBlockedNullIPResp(req *dns.Msg) (resp *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		resp, err = c.newMsgA(req, netip.Addr{})
	case dns.TypeAAAA:
		resp, err = c.newMsgAAAA(req, netip.Addr{})
	default:
		err = fmt.Errorf("bad qtype for an ip resp: %d", qt)
	}

	if err != nil {
		return nil, err
	}

	c.AddEDE(req, resp, dns.ExtendedErrorCodeFiltered)

	return resp, nil
}

// AddEDE adds an Extended DNS Error (EDE) option to the blocked response
// message, if the feature is enabled in the Constructor and the request
// indicates EDNS support.  It does not overwrite EDE if there already is one.
// req and resp must not be nil.
func (c *Constructor) AddEDE(req, resp *dns.Msg, code uint16) {
	if !c.edeEnabled {
		return
	}

	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		// Requestor doesn't implement EDNS, see
		// https://datatracker.ietf.org/doc/html/rfc6891#section-7.
		return
	}

	respOpt := resp.IsEdns0()
	if respOpt == nil {
		respOpt = newOPT(c.cloner, reqOpt.UDPSize(), reqOpt.Do())
		resp.Extra = append(resp.Extra, respOpt)
	} else if findEDE(respOpt) != nil {
		// Do not add an EDE option if there already is one.
		return
	}

	sdeText := c.sdeForReqOpt(reqOpt)

	respOpt.Option = append(respOpt.Option, newEDNS0EDE(c.cloner, code, sdeText))
}

// findEDE returns the EDE option if there is one.  opt must not be nil.
func findEDE(opt *dns.OPT) (ede *dns.EDNS0_EDE) {
	for _, o := range opt.Option {
		var ok bool
		if ede, ok = o.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}

	return nil
}

// sdeForReqOpt returns either the configured SDE text or empty string depending
// on the request's EDNS options.
func (c *Constructor) sdeForReqOpt(reqOpt *dns.OPT) (sde string) {
	ede := findEDE(reqOpt)
	if ede != nil && ede.InfoCode == 0 && ede.ExtraText == "" {
		return c.sde
	}

	return ""
}

// newBlockedCustomIPResp returns a blocked DNS response message with either the
// custom IPs from the blocking mode options or a NODATA one.
func (c *Constructor) newBlockedCustomIPResp(
	req *dns.Msg,
	m *BlockingModeCustomIP,
) (msg *dns.Msg, err error) {
	switch qt := req.Question[0].Qtype; qt {
	case dns.TypeA:
		if len(m.IPv4) > 0 {
			return c.NewBlockedRespIP(req, m.IPv4...)
		}
	case dns.TypeAAAA:
		if len(m.IPv6) > 0 {
			return c.NewBlockedRespIP(req, m.IPv6...)
		}
	default:
		// Go on.
	}

	msg = c.NewBlockedRespRCode(req, dns.RcodeSuccess)
	msg.Ns = c.newSOARecords(req)

	return msg, nil
}
