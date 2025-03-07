package initial

import (
	"context"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// TODO(a.garipov): Consider creating a new prefiltering package for this kind
// of filtering-before-filtering.

const (
	// ResolverARPADomain is the non-FQDN version of the DNS Resolver
	// Special-Use domain pointing to itself.
	//
	// See https://www.ietf.org/archive/id/draft-ietf-add-ddr-07.html#section-8.
	ResolverARPADomain = "resolver.arpa"

	// DDRLabel is the leading label of the special domain name for DDR.
	DDRLabel = "_dns"

	// DDRDomain is the non-FQDN version of the Discovery of Designated
	// Resolvers for querying the resolver with unknown or absent name.
	DDRDomain = DDRLabel + "." + ResolverARPADomain

	// ChromePrefetchHost is the hostname that Chrome uses to check if it should
	// use the Chrome Private Prefetch Proxy feature.
	//
	// See https://developer.chrome.com/docs/privacy-security/private-prefetch-proxy-for-network-admins.
	ChromePrefetchHost = "dns-tunnel-check.googlezip.net"

	// FirefoxCanaryHost is the hostname that Firefox uses to check if it should
	// use its own DNS-over-HTTPS settings.
	//
	// See https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https.
	FirefoxCanaryHost = "use-application-dns.net"
)

// Hostnames that Apple devices use to check if Apple Private Relay can be
// enabled.  Returning NXDOMAIN to queries for these domain names blocks Apple
// Private Relay.
//
// See https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay.
const (
	ApplePrivateRelayMaskHost       = "mask.icloud.com"
	ApplePrivateRelayMaskH2Host     = "mask-h2.icloud.com"
	ApplePrivateRelayMaskCanaryHost = "mask-canary.icloud.com"
)

// reqInfoSpecialHandler returns a handler that can handle a special-domain
// query based on the request info, as well as the handler's name for debugging.
func (mw *Middleware) reqInfoSpecialHandler(
	ri *agd.RequestInfo,
) (f reqInfoHandlerFunc, name string) {
	if ri.QClass != dns.ClassINET {
		return nil, ""
	}

	// As per RFC-9462 section 6.4, resolvers SHOULD respond to queries of any
	// type other than SVCB for _dns.resolver.arpa. with NODATA and queries of
	// any type for any domain name under resolver.arpa with NODATA.
	//
	// TODO(e.burkov):  Consider adding SOA records for these NODATA responses.
	if mw.isDDRRequest(ri) {
		if _, ok := ri.DeviceResult.(*agd.DeviceResultAuthenticationFailure); ok {
			return mw.handleDDRNoData, "ddr_doh"
		}

		_, dev := ri.DeviceData()
		if dev != nil && dev.Auth.Enabled && dev.Auth.DoHAuthOnly {
			return mw.handleDDRNoData, "ddr_doh"
		}

		return mw.handleDDR, "ddr"
	} else if netutil.IsSubdomain(ri.Host, ResolverARPADomain) {
		// A badly formed resolver.arpa subdomain query.
		return mw.handleBadResolverARPA, "bad_resolver_arpa"
	}

	return mw.specialDomainHandler(ri)
}

// reqInfoHandlerFunc is an alias for handler functions that additionally accept
// request info.
type reqInfoHandlerFunc func(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error)

// isDDRRequest determines if the message is the request for Discovery of
// Designated Resolvers as defined by the RFC draft.  The request is considered
// ARPA if the requested host is a subdomain of resolver.arpa SUDN.
//
// See https://datatracker.ietf.org/doc/html/draft-ietf-add-ddr-07.
func (mw *Middleware) isDDRRequest(ri *agd.RequestInfo) (ok bool) {
	if ri.QType != dns.TypeSVCB {
		// Resolvers should respond to queries of any type other than SVCB for
		// _dns.resolver.arpa with NODATA and queries of any type for any domain
		// name under resolver.arpa with NODATA.
		//
		// See https://www.ietf.org/archive/id/draft-ietf-add-ddr-06.html#section-6.4.
		return false
	}

	host := ri.Host
	if host == DDRDomain {
		// A simple resolver.arpa request.
		return true
	}

	return mw.isDDRDomain(ri, host)
}

// isDDRDomain returns true if host is a DDR domain.
func (mw *Middleware) isDDRDomain(ri *agd.RequestInfo, host string) (ok bool) {
	firstLabel, resolverDomain, cut := strings.Cut(host, ".")
	if !cut || firstLabel != DDRLabel {
		return false
	}

	if mw.ddr.PublicTargets.Has(resolverDomain) {
		// The client may simply send a DNS SVCB query using the known name of
		// the resolver.  This query can be issued to the named Encrypted
		// Resolver itself or to any other resolver.  Unlike the case of
		// bootstrapping from an Unencrypted Resolver, these records should be
		// available in the public DNS.
		return true
	}

	_, dev := ri.DeviceData()
	if dev == nil {
		return false
	}

	firstLabel, resolverDomain, cut = strings.Cut(resolverDomain, ".")
	if cut && firstLabel == string(dev.ID) {
		// A request for the device ID resolver domain.
		return mw.ddr.DeviceTargets.Has(resolverDomain)
	}

	return false
}

// handleDDR responds to Discovery of Designated Resolvers (DDR) queries with a
// response containing the designated resolvers.
func (mw *Middleware) handleDDR(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	defer func() { err = errors.Annotate(err, "writing ddr resp for %q: %w", ri.Host) }()

	metrics.DNSSvcDDRRequestsTotal.Inc()

	if mw.ddr.Enabled {
		return rw.WriteMsg(ctx, req, mw.newRespDDR(req, ri))
	}

	return rw.WriteMsg(ctx, req, ri.Messages.NewRespRCode(req, dns.RcodeNameError))
}

// handleDDRNoData responds to Discovery of Designated Resolvers (DDR) queries
// with a NODATA response.
func (mw *Middleware) handleDDRNoData(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	defer func() { err = errors.Annotate(err, "writing ddr resp for %q: %w", ri.Host) }()

	metrics.DNSSvcDDRRequestsTotal.Inc()

	if mw.ddr.Enabled {
		return rw.WriteMsg(ctx, req, ri.Messages.NewRespRCode(req, dns.RcodeSuccess))
	}

	return rw.WriteMsg(ctx, req, ri.Messages.NewRespRCode(req, dns.RcodeNameError))
}

// newRespDDR returns a new Discovery of Designated Resolvers response copying
// it from the prebuilt templates in srvGrp and modifying it in accordance with
// the request data.  req must not be nil.
func (mw *Middleware) newRespDDR(req *dns.Msg, ri *agd.RequestInfo) (resp *dns.Msg) {
	resp = ri.Messages.NewResp(req)
	name := req.Question[0].Name

	// TODO(a.garipov):  Optimize calls to ri.DeviceData.
	if _, dev := ri.DeviceData(); dev != nil {
		for _, rr := range mw.ddr.DeviceRecordTemplates {
			rr = dns.Copy(rr).(*dns.SVCB)
			rr.Hdr.Name = name
			rr.Target = string(dev.ID) + "." + rr.Target

			resp.Answer = append(resp.Answer, rr)
		}

		return resp
	}

	for _, rr := range mw.ddr.PublicRecordTemplates {
		rr = dns.Copy(rr).(*dns.SVCB)
		rr.Hdr.Name = name

		resp.Answer = append(resp.Answer, rr)
	}

	return resp
}

// handleBadResolverARPA responds to badly formed resolver.arpa queries with a
// NODATA response.
func (mw *Middleware) handleBadResolverARPA(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcBadResolverARPA.Inc()

	resp := ri.Messages.NewRespRCode(req, dns.RcodeSuccess)
	err = rw.WriteMsg(ctx, req, resp)

	return errors.Annotate(err, "writing nodata resp for %q: %w", ri.Host)
}

// specialDomainHandler returns a handler that can handle a special-domain
// query for Apple Private Relay or Firefox canary domain based on the request
// or profile information, as well as the handler's name for debugging.
func (mw *Middleware) specialDomainHandler(
	ri *agd.RequestInfo,
) (f reqInfoHandlerFunc, name string) {
	qt := ri.QType
	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return nil, ""
	}

	host := ri.Host
	prof, _ := ri.DeviceData()

	switch host {
	case
		ApplePrivateRelayMaskHost,
		ApplePrivateRelayMaskH2Host,
		ApplePrivateRelayMaskCanaryHost:
		if shouldBlockPrivateRelay(ri, prof) {
			return mw.handlePrivateRelay, "apple_private_relay"
		}
	case ChromePrefetchHost:
		if shouldBlockChromePrefetch(ri, prof) {
			return mw.handleChromePrefetch, "chrome_prefetch"
		}
	case FirefoxCanaryHost:
		if shouldBlockFirefoxCanary(ri, prof) {
			return mw.handleFirefoxCanary, "firefox"
		}
	default:
		// Go on.
	}

	return nil, ""
}

// shouldBlockChromePrefetch returns true request information or profile
// indicate that the Chrome prefetch domain should be blocked.
func shouldBlockChromePrefetch(ri *agd.RequestInfo, prof *agd.Profile) (ok bool) {
	if prof != nil {
		return prof.BlockChromePrefetch
	}

	return ri.FilteringGroup.BlockChromePrefetch
}

// handleChromePrefetch responds to Chrome prefetch domain queries with an
// NXDOMAIN response.
func (mw *Middleware) handleChromePrefetch(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcChromePrefetchRequestsTotal.Inc()

	resp := ri.Messages.NewRespRCode(req, dns.RcodeNameError)
	err = rw.WriteMsg(ctx, req, resp)

	return errors.Annotate(err, "writing chrome prefetch resp: %w")
}

// shouldBlockFirefoxCanary returns true request information or profile indicate
// that the Firefox canary domain should be blocked.
func shouldBlockFirefoxCanary(ri *agd.RequestInfo, prof *agd.Profile) (ok bool) {
	if prof != nil {
		return prof.BlockFirefoxCanary
	}

	return ri.FilteringGroup.BlockFirefoxCanary
}

// handleFirefoxCanary responds to Firefox canary domain queries with a REFUSED
// response.
func (mw *Middleware) handleFirefoxCanary(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcFirefoxRequestsTotal.Inc()

	resp := ri.Messages.NewRespRCode(req, dns.RcodeRefused)
	err = rw.WriteMsg(ctx, req, resp)

	return errors.Annotate(err, "writing firefox canary resp: %w")
}

// shouldBlockPrivateRelay returns true request information or profile indicate
// that the Apple Private Relay domain should be blocked.
func shouldBlockPrivateRelay(ri *agd.RequestInfo, prof *agd.Profile) (ok bool) {
	if prof != nil {
		return prof.BlockPrivateRelay
	}

	return ri.FilteringGroup.BlockPrivateRelay
}

// handlePrivateRelay responds to Apple Private Relay queries with an NXDOMAIN
// response.
func (mw *Middleware) handlePrivateRelay(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcApplePrivateRelayRequestsTotal.Inc()

	resp := ri.Messages.NewRespRCode(req, dns.RcodeNameError)
	err = rw.WriteMsg(ctx, req, resp)

	return errors.Annotate(err, "writing private relay resp: %w")
}
