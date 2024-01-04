package mainmw

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
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

	prof := ri.Profile
	if prof == nil {
		return
	}

	var devID agd.DeviceID
	if d := ri.Device; d != nil {
		devID = d.ID
	}

	var reqCtry geoip.Country
	var reqASN geoip.ASN
	if g := ri.Location; g != nil {
		reqCtry, reqASN = g.Country, g.ASN
	}

	reqInfo := dnsserver.MustRequestInfoFromContext(ctx)
	start := reqInfo.StartTime
	mw.billStat.Record(ctx, devID, reqCtry, reqASN, start, ri.Proto)

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
		ResponseCountry: mw.responseCountry(ctx, fctx, ri, respIP),
		DomainFQDN:      q.Name,
		ClientASN:       reqASN,
		Elapsed:         uint16(time.Since(start).Milliseconds()),
		RequestType:     ri.QType,
		Protocol:        ri.Proto,
		DNSSEC:          respDNSSEC,
		ResponseCode:    rcode,
		RemoteIP:        clientIP,
	}

	err := mw.queryLog.Write(ctx, e)
	if err != nil {
		// Consider query logging errors non-critical.
		mw.reportf(ctx, "writing query log: %w", err)
	}
}

// responseCountry returns the country of the response IP address based on the
// request and filtering data.
func (mw *Middleware) responseCountry(
	ctx context.Context,
	fctx *filteringContext,
	ri *agd.RequestInfo,
	respIP netip.Addr,
) (ctry geoip.Country) {
	if respIP == (netip.Addr{}) || respIP.IsUnspecified() {
		return geoip.CountryNone
	}

	host := ri.Host
	if modReq := fctx.modifiedRequest; modReq != nil {
		// If the request was modified by CNAME rule, the actual result
		// belongs to the hostname from that CNAME.
		host = agdnet.NormalizeDomain(modReq.Question[0].Name)
	}

	return mw.country(ctx, host, respIP)
}

// responseData is a helper that returns the response code, the first IP
// address, and the DNSSEC AD flag from the DNS query response if the answer has
// the type of A or AAAA or an empty IP address otherwise.
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

	var rrType dns.Type
	var fam netutil.AddrFamily
	var netIP net.IP
	dnssec = resp.AuthenticatedData
	rcode = dnsmsg.RCode(resp.Rcode)
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			fam = netutil.AddrFamilyIPv4
			rrType, netIP = dns.Type(v.Hdr.Rrtype), v.A
		case *dns.AAAA:
			fam = netutil.AddrFamilyIPv6
			rrType, netIP = dns.Type(v.Hdr.Rrtype), v.AAAA
		default:
			continue
		}

		break
	}

	if netIP != nil {
		var err error
		ip, err = netutil.IPToAddr(netIP, fam)
		if err != nil {
			mw.reportf(ctx, "converting %s resp data: %w", rrType, err)
		}
	}

	return rcode, ip, dnssec
}

// country is a wrapper around the GeoIP call that contains the handling of
// non-critical GeoIP errors.
func (mw *Middleware) country(ctx context.Context, host string, ip netip.Addr) (c geoip.Country) {
	l, err := mw.geoIP.Data(host, ip)
	if err != nil {
		// Consider GeoIP errors non-critical.
		mw.reportf(ctx, "getting geoip data: %w", err)
	}

	if l != nil {
		return l.Country
	}

	return geoip.CountryNone
}
