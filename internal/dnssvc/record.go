package dnssvc

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Query Logging, Billing, And Statistics Recording

// recordQueryInfo extracts loggable information from request, response, and
// filtering data and writes them to the query log, billing, and filtering-rule
// statistics, handling non-critical errors.
func (svc *Service) recordQueryInfo(
	ctx context.Context,
	req *dns.Msg,
	resp *dns.Msg,
	origResp *dns.Msg,
	ri *agd.RequestInfo,
	reqRes filter.Result,
	respRes filter.Result,
) {
	id, text, blocked := filteringData(reqRes, respRes)
	svc.ruleStat.Collect(ctx, id, text)

	prof := ri.Profile
	if prof == nil {
		return
	}

	var devID agd.DeviceID
	if d := ri.Device; d != nil {
		devID = d.ID
	}

	var reqCtry agd.Country
	var reqASN agd.ASN
	if g := ri.Location; g != nil {
		reqCtry, reqASN = g.Country, g.ASN
	}

	proto := dnsserver.MustServerInfoFromContext(ctx).Proto
	start := dnsserver.MustStartTimeFromContext(ctx)
	svc.billStat.Record(ctx, devID, reqCtry, reqASN, start, proto)

	if !prof.QueryLogEnabled {
		return
	}

	rcode, respIP, respDNSSEC := svc.responseData(ctx, resp)
	if blocked {
		// If the request or the response were blocked, resp may contain an
		// unspecified IP address, a rewritten IP address, or none at all, while
		// the original response may contain an actual IP address that should be
		// used to determine the response country.
		_, respIP, _ = svc.responseData(ctx, origResp)
	}

	var respCtry agd.Country
	if !respIP.IsUnspecified() {
		host := ri.Host
		if modReq := rewrittenRequest(reqRes); modReq != nil {
			// If the request was modified by CNAME rule, the actual result
			// belongs to the hostname from that CNAME.
			host = strings.TrimSuffix(modReq.Question[0].Name, ".")
		}

		respCtry = svc.country(ctx, host, respIP)
	}

	q := req.Question[0]
	e := &querylog.Entry{
		RequestResult:   reqRes,
		ResponseResult:  respRes,
		Time:            start,
		RequestID:       ri.ID,
		ProfileID:       prof.ID,
		DeviceID:        devID,
		ClientCountry:   reqCtry,
		ResponseCountry: respCtry,
		DomainFQDN:      q.Name,
		ClientASN:       reqASN,
		Elapsed:         uint16(time.Since(start).Milliseconds()),
		RequestType:     q.Qtype,
		Protocol:        proto,
		DNSSEC:          respDNSSEC,
		ResponseCode:    rcode,
	}

	err := svc.queryLog.Write(ctx, e)
	if err != nil {
		// Consider query logging errors non-critical.
		svc.reportf(ctx, "writing query log: %w", err)
	}
}

// filteringData returns the data necessary for request information recording
// from the request and response filtering results.
func filteringData(
	reqRes, respRes filter.Result,
) (id agd.FilterListID, text agd.FilterRuleText, blocked bool) {
	if reqRes != nil {
		return resultData(reqRes, "reqRes")
	}

	return resultData(respRes, "respRes")
}

// resultData returns the data necessary for request information recording from
// one filtering result.  argName is used to provide better error handling.
func resultData(
	res filter.Result,
	argName string,
) (id agd.FilterListID, text agd.FilterRuleText, blocked bool) {
	if res == nil {
		return agd.FilterListIDNone, "", false
	}

	id, text = res.MatchedRule()
	switch res := res.(type) {
	case *filter.ResultAllowed:
		blocked = false
	case
		*filter.ResultBlocked,
		*filter.ResultModified:
		blocked = true
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    argName,
			Message: fmt.Sprintf("unexpected type %T", res),
		})
	}

	return id, text, blocked
}

// responseData is a helper that returns the response code, the first IP
// address, and the DNSSEC AD flag from the DNS query response if the answer has
// the type of A or AAAA or a nil IP address otherwise.
//
// If resp is nil or contains invalid data, it returns 0xff (an unassigned
// RCODE), net.Addr{}, and false.  It reports all errors using svc.reportf.
func (svc *Service) responseData(
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
			svc.reportf(ctx, "converting %s resp data: %w", rrType, err)
		}
	}

	return rcode, ip, dnssec
}

// country is a wrapper around the GeoIP call that contains the handling of
// non-critical GeoIP errors.
func (svc *Service) country(ctx context.Context, host string, ip netip.Addr) (c agd.Country) {
	l, err := svc.geoIP.Data(host, ip)
	if err != nil {
		// Consider GeoIP errors non-critical.
		svc.reportf(ctx, "getting geoip data: %w", err)
	} else if l == nil {
		return agd.CountryNone
	}

	return l.Country
}
