package mainmw

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// recordQueryInfo extracts loggable information from request, response, and
// filtering data and writes them to the query log, billing, and filtering-rule
// statistics, handling non-critical errors.
func (mw *Middleware) recordQueryInfo(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
) {
	id, text, blocked := filteringData(fctx)
	mw.ruleStat.Collect(ctx, id, text)

	prof, dev := ri.DeviceData()
	if prof == nil {
		return
	}

	devID := dev.ID

	var reqCtry geoip.Country
	var reqASN geoip.ASN
	if g := ri.Location; g != nil {
		reqCtry, reqASN = g.Country, g.ASN
	}

	reqInfo := dnsserver.MustRequestInfoFromContext(ctx)
	start := reqInfo.StartTime
	mw.billStat.Record(ctx, devID, reqCtry, reqASN, start, ri.ServerInfo.Protocol)

	if !prof.QueryLogEnabled {
		return
	}

	rcode, respIP, respDNSSEC := mw.responseData(ctx, fctx.filteredResponse)
	if blocked {
		// If the request or the response were blocked, resp may contain an
		// unspecified IP address, a rewritten IP address, or none at all, while
		// the original response may contain an actual IP address that should be
		// used to determine the response country.
		_, respIP, _ = mw.responseData(ctx, fctx.originalResponse)
	}

	var clientIP netip.Addr
	if prof.IPLogEnabled {
		clientIP = ri.RemoteIP
	}

	q := fctx.originalRequest.Question[0]
	e := &querylog.Entry{
		RequestResult:   fctx.requestResult,
		ResponseResult:  fctx.responseResult,
		Time:            start,
		RequestID:       ri.ID,
		ProfileID:       prof.ID,
		DeviceID:        devID,
		ClientCountry:   reqCtry,
		ResponseCountry: mw.responseCountry(ctx, fctx, ri.Host, respIP, rcode),
		DomainFQDN:      q.Name,
		Elapsed:         time.Since(start),
		ClientASN:       reqASN,
		RequestType:     ri.QType,
		ResponseCode:    rcode,
		Protocol:        ri.ServerInfo.Protocol,
		DNSSEC:          respDNSSEC,
		RemoteIP:        clientIP,
	}

	err := mw.queryLog.Write(ctx, e)
	if err != nil {
		// Consider query logging errors non-critical.
		errcoll.Collect(ctx, mw.errColl, mw.logger, "writing query log", err)
	}
}

// responseCountry returns the country of the response IP address based on the
// request and filtering data.  If rcode is not a NOERROR one or there is no
// IP-address data in the response, ctry is [geoip.CountryNotApplicable].
func (mw *Middleware) responseCountry(
	ctx context.Context,
	fctx *filteringContext,
	host string,
	respIP netip.Addr,
	rcode dnsmsg.RCode,
) (ctry geoip.Country) {
	if rcode != dns.RcodeSuccess || respIP == (netip.Addr{}) || respIP.IsUnspecified() {
		return geoip.CountryNotApplicable
	}

	if modReq := fctx.modifiedRequest; modReq != nil {
		// If the request was modified by CNAME rule, the actual result
		// belongs to the hostname from that CNAME.
		host = agdnet.NormalizeDomain(modReq.Question[0].Name)
	}

	ctry = mw.country(ctx, host, respIP)
	optslog.Trace2(ctx, mw.logger, "geoip for resp", "ctry", ctry, "resp_ip", respIP)

	return ctry
}

// responseData is a helper that returns the response code, the first IP
// address, and the DNSSEC AD flag from the DNS query response if the answer has
// the type of A, AAAA, or HTTPS or an empty IP address otherwise.
//
// If resp is nil or contains invalid data, it returns 0xff (an unassigned
// RCODE), net.Addr{}, and false.  It reports all errors using
// [Middleware.reportf].
func (mw *Middleware) responseData(
	ctx context.Context,
	resp *dns.Msg,
) (rcode dnsmsg.RCode, ip netip.Addr, dnssec bool) {
	if resp == nil {
		return 0xff, netip.Addr{}, false
	}

	dnssec = resp.AuthenticatedData
	// #nosec G115 -- RCODE is currently defined to be 16 bit or less.
	rcode = dnsmsg.RCode(resp.Rcode)

	ip, err := ipFromAnswer(resp.Answer)
	if err != nil {
		errcoll.Collect(ctx, mw.errColl, mw.logger, "getting response data", err)
	}

	return rcode, ip, dnssec
}

// ipFromAnswer returns the first IP address from the answer resource records.
func ipFromAnswer(answer []dns.RR) (ip netip.Addr, err error) {
	var rrType dns.Type
	var fam netutil.AddrFamily
	var netIP net.IP
	for _, rr := range answer {
		switch v := rr.(type) {
		case *dns.A:
			fam = netutil.AddrFamilyIPv4
			rrType, netIP = dns.Type(v.Hdr.Rrtype), v.A
		case *dns.AAAA:
			fam = netutil.AddrFamilyIPv6
			rrType, netIP = dns.Type(v.Hdr.Rrtype), v.AAAA
		case *dns.HTTPS:
			return ipFromHTTPSRR(v)
		default:
			continue
		}

		break
	}

	if netIP == nil {
		return netip.Addr{}, nil
	}

	ip, err = netutil.IPToAddr(netIP, fam)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("converting %s resp data: %w", rrType, err)
	}

	return ip, nil
}

// ipFromHTTPSRR returns the data for the first IP hint in an HTTPS resource
// record.
func ipFromHTTPSRR(https *dns.HTTPS) (ip netip.Addr, err error) {
	var fam netutil.AddrFamily
	var netIP net.IP
	for _, v := range https.Value {
		fam, netIP = ipFromHTTPSRRKV(v)
		if fam != netutil.AddrFamilyNone {
			break
		}
	}

	if netIP == nil {
		return netip.Addr{}, nil
	}

	ip, err = netutil.IPToAddr(netIP, fam)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("converting https rr %s hint data: %w", fam, err)
	}

	return ip, nil
}

// ipFromHTTPSRRKV returns the IP-address data from the IP hint of an HTTPS
// resource record.  If the hint does not contain an IP address, fam is
// [netutil.AddrFamilyNone] and netIP is nil.
func ipFromHTTPSRRKV(kv dns.SVCBKeyValue) (fam netutil.AddrFamily, netIP net.IP) {
	switch kv := kv.(type) {
	case *dns.SVCBIPv4Hint:
		if len(kv.Hint) > 0 {
			return netutil.AddrFamilyIPv4, kv.Hint[0]
		}
	case *dns.SVCBIPv6Hint:
		if len(kv.Hint) > 0 {
			return netutil.AddrFamilyIPv6, kv.Hint[0]
		}
	default:
		// Go on.
	}

	return netutil.AddrFamilyNone, nil
}

// country is a wrapper around the GeoIP call that contains the handling of
// non-critical GeoIP errors.
func (mw *Middleware) country(ctx context.Context, host string, ip netip.Addr) (c geoip.Country) {
	l, err := mw.geoIP.Data(ctx, host, ip)
	if err != nil {
		// Consider GeoIP errors non-critical.
		errcoll.Collect(ctx, mw.errColl, mw.logger, "getting geoip data", err)
	}

	if l != nil {
		return l.Country
	}

	return geoip.CountryNone
}
