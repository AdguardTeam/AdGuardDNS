package dnsmsg

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// NewAnswerHTTPS returns a properly initialized HTTPS resource record.
//
// See the comment on NewAnswerSVCB for a list of current restrictions on
// parameter values.
func (c *Constructor) NewAnswerHTTPS(req *dns.Msg, svcb *rules.DNSSVCB) (ans *dns.HTTPS) {
	ans = &dns.HTTPS{
		SVCB: *c.NewAnswerSVCB(req, svcb),
	}

	ans.Hdr.Rrtype = dns.TypeHTTPS

	return ans
}

// strToSVCBKey is the string-to-svcb-key mapping.
//
// See https://github.com/miekg/dns/blob/23c4faca9d32b0abbb6e179aa1aadc45ac53a916/svcb.go#L27.
//
// TODO(a.garipov): Propose exporting this API or something similar in the
// github.com/miekg/dns module.
var strToSVCBKey = map[string]dns.SVCBKey{
	"alpn":            dns.SVCB_ALPN,
	"dohpath":         dns.SVCB_DOHPATH,
	"ech":             dns.SVCB_ECHCONFIG,
	"ipv4hint":        dns.SVCB_IPV4HINT,
	"ipv6hint":        dns.SVCB_IPV6HINT,
	"mandatory":       dns.SVCB_MANDATORY,
	"no-default-alpn": dns.SVCB_NO_DEFAULT_ALPN,
	"port":            dns.SVCB_PORT,
}

// svcbKeyHandler is a handler for one SVCB parameter key.
type svcbKeyHandler func(valStr string) (val dns.SVCBKeyValue)

// svcbKeyHandlers are the supported SVCB parameters handlers.
var svcbKeyHandlers = map[string]svcbKeyHandler{
	"alpn": func(valStr string) (val dns.SVCBKeyValue) {
		return &dns.SVCBAlpn{
			Alpn: []string{valStr},
		}
	},

	"dohpath": func(valStr string) (val dns.SVCBKeyValue) {
		return &dns.SVCBDoHPath{
			Template: valStr,
		}
	},

	"ech": func(valStr string) (val dns.SVCBKeyValue) {
		ech, err := base64.StdEncoding.DecodeString(valStr)
		if err != nil {
			return nil
		}

		return &dns.SVCBECHConfig{
			ECH: ech,
		}
	},

	"ipv4hint": func(valStr string) (val dns.SVCBKeyValue) {
		ip := net.ParseIP(valStr)
		if ip4 := ip.To4(); ip == nil || ip4 == nil {
			return nil
		}

		return &dns.SVCBIPv4Hint{
			Hint: []net.IP{ip},
		}
	},

	"ipv6hint": func(valStr string) (val dns.SVCBKeyValue) {
		ip := net.ParseIP(valStr)
		if ip == nil {
			return nil
		}

		return &dns.SVCBIPv6Hint{
			Hint: []net.IP{ip},
		}
	},

	"mandatory": func(valStr string) (val dns.SVCBKeyValue) {
		code, ok := strToSVCBKey[valStr]
		if !ok {
			return nil
		}

		return &dns.SVCBMandatory{
			Code: []dns.SVCBKey{code},
		}
	},

	"no-default-alpn": func(_ string) (val dns.SVCBKeyValue) {
		return &dns.SVCBNoDefaultAlpn{}
	},

	"port": func(valStr string) (val dns.SVCBKeyValue) {
		port64, err := strconv.ParseUint(valStr, 10, 16)
		if err != nil {
			return nil
		}

		return &dns.SVCBPort{
			Port: uint16(port64),
		}
	},
}

// NewAnswerSVCB returns a properly initialized SVCB resource record.
//
// Currently, there are several restrictions on how the parameters are parsed.
// Firstly, the parsing of non-contiguous values isn't supported.  Secondly, the
// parsing of value-lists is not supported either.
//
//	ipv4hint=127.0.0.1             // Supported.
//	ipv4hint="127.0.0.1"           // Unsupported.
//	ipv4hint=127.0.0.1,127.0.0.2   // Unsupported.
//	ipv4hint="127.0.0.1,127.0.0.2" // Unsupported.
//
// TODO(a.garipov):  Support all of these.
//
// TODO(a.garipov):  Consider re-adding debug logging for SVCB handlers.
func (c *Constructor) NewAnswerSVCB(req *dns.Msg, svcb *rules.DNSSVCB) (ans *dns.SVCB) {
	ans = &dns.SVCB{
		Hdr:      c.newHdr(req, dns.TypeSVCB),
		Priority: svcb.Priority,
		Target:   dns.Fqdn(svcb.Target),
	}
	if len(svcb.Params) == 0 {
		return ans
	}

	values := make([]dns.SVCBKeyValue, 0, len(svcb.Params))
	for k, valStr := range svcb.Params {
		handler, ok := svcbKeyHandlers[k]
		if !ok {
			continue
		}

		val := handler(valStr)
		if val == nil {
			continue
		}

		values = append(values, val)
	}

	if len(values) > 0 {
		ans.Value = values
	}

	return ans
}

// NewDDRTemplate returns a single Discovery of Designated Resolvers response
// resource record template specific for a resolver.  The returned resource
// record doesn't specify a name in its header since it may differ between
// requests, so it's not a valid record as is.
//
// If the IP address arguments aren't empty, their elements will be added into
// the appropriate hints.  Those arguments are assumed to be of the correct
// protocol version.
//
// proto must be a standard encrypted protocol, as defined by
// dnsserver.Protocol.IsStdEncrypted.
//
// TODO(a.garipov): Remove the dependency on package dnsserver.
func (c *Constructor) NewDDRTemplate(
	proto dnsserver.Protocol,
	resolverName string,
	dohPath string,
	ipv4Hints []netip.Addr,
	ipv6Hints []netip.Addr,
	port uint16,
	prio uint16,
) (rr *dns.SVCB) {
	if !proto.IsStdEncrypted() {
		// TODO(e.burkov):  Build a more complete error message with structured
		// data about allowed values.
		panic(fmt.Errorf("bad proto %s for ddr", proto))
	}

	keyVals := []dns.SVCBKeyValue{
		&dns.SVCBAlpn{Alpn: proto.ALPN()},
		&dns.SVCBPort{Port: port},
	}

	if proto == dnsserver.ProtoDoH && dohPath != "" {
		keyVals = append(keyVals, &dns.SVCBDoHPath{Template: dohPath})
	}

	if len(ipv4Hints) > 0 {
		hint := make([]net.IP, len(ipv4Hints))
		for i, addr := range ipv4Hints {
			hint[i] = addr.AsSlice()
		}

		keyVals = append(keyVals, &dns.SVCBIPv4Hint{Hint: hint})
	}

	if len(ipv6Hints) > 0 {
		hint := make([]net.IP, len(ipv6Hints))
		for i, addr := range ipv6Hints {
			hint[i] = addr.AsSlice()
		}

		keyVals = append(keyVals, &dns.SVCBIPv6Hint{Hint: hint})
	}

	rr = &dns.SVCB{
		Hdr: dns.RR_Header{
			// Keep the name empty for the client of the API to fill it.
			Name:   "",
			Rrtype: dns.TypeSVCB,
			Ttl:    uint32(c.fltRespTTL.Seconds()),
			Class:  dns.ClassINET,
		},
		Priority: prio,
		Target:   dns.Fqdn(resolverName),
		Value:    keyVals,
	}

	return rr
}
