package dnssvc

import (
	"context"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Handling For Special Purpose Requests
//
// TODO(a.garipov): Consider creating a new prefiltering package for this kind
// of filtering-before-filtering.

const (
	// resolverArpaDomain is the non-FQDN version of the DNS Resolver
	// Special-Use domain pointing to itself.
	//
	// See https://www.ietf.org/archive/id/draft-ietf-add-ddr-07.html#section-8.
	resolverArpaDomain = "resolver.arpa"

	// ddrLabel is the leading label of the special domain name for DDR.
	ddrLabel = "_dns"

	// ddrDomain is the non-FQDN version of the Discovery of Designated
	// Resolvers for querying the resolver with unknown or absent name.
	ddrDomain = ddrLabel + "." + resolverArpaDomain

	// firefoxCanaryFQDN is the fully-qualified canary domain that Firefox uses
	// to check if it should use its own DNS-over-HTTPS settings.
	//
	// See https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https.
	firefoxCanaryFQDN = "use-application-dns.net."

	// applePrivateRelayMaskHost and applePrivateRelayMaskH2Host are the
	// hostnames that Apple devices use to check if Apple Private Relay can be
	// enabled.  Returning NXDOMAIN to queries for these domain names blocks
	// Apple Private Relay.
	//
	// See https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay.
	applePrivateRelayMaskHost   = "mask.icloud.com"
	applePrivateRelayMaskH2Host = "mask-h2.icloud.com"
)

// noReqInfoSpecialHandler returns a handler that can handle a special-domain
// query based only on its question type, class, and target, as well as the
// handler's name for debugging.
func (mw *initMw) noReqInfoSpecialHandler(
	fqdn string,
	qt dnsmsg.RRType,
	cl dnsmsg.Class,
) (f dnsserver.HandlerFunc, name string) {
	if cl != dns.ClassINET {
		return nil, ""
	}

	if (qt == dns.TypeA || qt == dns.TypeAAAA) && fqdn == firefoxCanaryFQDN {
		return mw.handleFirefoxCanary, "firefox"
	}

	return nil, ""
}

// Firefox Canary

// handleFirefoxCanary checks if the request is for the fully-qualified domain
// name that Firefox uses to check DoH settings and writes a response if needed.
func (mw *initMw) handleFirefoxCanary(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	metrics.DNSSvcFirefoxRequestsTotal.Inc()

	resp := mw.messages.NewMsgREFUSED(req)
	err = rw.WriteMsg(ctx, req, resp)

	return errors.Annotate(err, "writing firefox canary resp: %w")
}

// reqInfoSpecialHandler returns a handler that can handle a special-domain
// query based on the request info, as well as the handler's name for debugging.
func (mw *initMw) reqInfoSpecialHandler(
	ri *agd.RequestInfo,
	cl dnsmsg.Class,
) (f reqInfoHandlerFunc, name string) {
	if cl != dns.ClassINET {
		return nil, ""
	}

	if mw.isDDRRequest(ri) {
		return mw.handleDDR, "ddr"
	} else if netutil.IsSubdomain(ri.Host, resolverArpaDomain) {
		// A badly formed resolver.arpa subdomain query.
		return mw.handleBadResolverARPA, "bad_resolver_arpa"
	} else if shouldBlockPrivateRelay(ri) {
		return mw.handlePrivateRelay, "apple_private_relay"
	}

	return nil, ""
}

// reqInfoHandlerFunc is an alias for handler functions that additionally accept
// request info.
type reqInfoHandlerFunc func(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error)

// DDR And Resolver ARPA Domain

// isDDRRequest determines if the message is the request for Discovery of
// Designated Resolvers as defined by the RFC draft.  The request is considered
// ARPA if the requested host is a subdomain of resolver.arpa SUDN.
//
// See https://datatracker.ietf.org/doc/html/draft-ietf-add-ddr-07.
func (mw *initMw) isDDRRequest(ri *agd.RequestInfo) (ok bool) {
	if ri.QType != dns.TypeSVCB {
		// Resolvers should respond to queries of any type other than SVCB for
		// _dns.resolver.arpa with NODATA and queries of any type for any domain
		// name under resolver.arpa with NODATA.
		//
		// See https://www.ietf.org/archive/id/draft-ietf-add-ddr-06.html#section-6.4.
		return false
	}

	host := ri.Host
	if host == ddrDomain {
		// A simple resolver.arpa request.
		return true
	}

	if firstLabel, resolverDomain, cut := strings.Cut(host, "."); cut && firstLabel == ddrLabel {
		ddr := mw.srvGrp.DDR
		if ddr.PublicTargets.Has(resolverDomain) {
			// The client may simply send a DNS SVCB query using the known name
			// of the resolver.  This query can be issued to the named Encrypted
			// Resolver itself or to any other resolver.  Unlike the case of
			// bootstrapping from an Unencrypted Resolver, these records should
			// be available in the public DNS.
			return true
		}

		firstLabel, resolverDomain, cut = strings.Cut(resolverDomain, ".")
		if cut && ri.Device != nil && firstLabel == string(ri.Device.ID) {
			// A request for the device ID resolver domain.
			return ddr.DeviceTargets.Has(resolverDomain)
		}
	}

	return false
}

// handleDDR checks if the request is for the Discovery of Designated Resolvers
// and writes a response if needed.
func (mw *initMw) handleDDR(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcDDRRequestsTotal.Inc()

	if mw.srvGrp.DDR.Enabled {
		err = rw.WriteMsg(ctx, req, mw.newRespDDR(req, ri.Device))
	} else {
		err = rw.WriteMsg(ctx, req, ri.Messages.NewMsgNXDOMAIN(req))
	}

	return errors.Annotate(err, "writing ddr resp for %q: %w", ri.Host)
}

// newRespDDR returns a new Discovery of Designated Resolvers response copying
// it from the prebuilt templates in srvGrp and modifying it in accordance with
// the request data.  req must not be nil.
func (mw *initMw) newRespDDR(req *dns.Msg, dev *agd.Device) (resp *dns.Msg) {
	resp = mw.messages.NewRespMsg(req)
	name := req.Question[0].Name
	ddr := mw.srvGrp.DDR

	if dev != nil {
		for _, rr := range ddr.DeviceRecordTemplates {
			rr = dns.Copy(rr).(*dns.SVCB)
			rr.Hdr.Name = name
			rr.Target = string(dev.ID) + "." + rr.Target

			resp.Answer = append(resp.Answer, rr)
		}

		return resp
	}

	for _, rr := range ddr.PublicRecordTemplates {
		rr = dns.Copy(rr).(*dns.SVCB)
		rr.Hdr.Name = name

		resp.Answer = append(resp.Answer, rr)
	}

	return resp
}

// handleBadResolverARPA writes a NODATA response.
func (mw *initMw) handleBadResolverARPA(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcBadResolverARPA.Inc()

	err = rw.WriteMsg(ctx, req, ri.Messages.NewRespMsg(req))

	return errors.Annotate(err, "writing nodata resp for %q: %w", ri.Host)
}

// Apple Private Relay

// shouldBlockPrivateRelay returns true if the query is for an Apple Private
// Relay check domain and the request information indicates that Apple Private
// Relay should be blocked.
func shouldBlockPrivateRelay(ri *agd.RequestInfo) (ok bool) {
	qt := ri.QType
	host := ri.Host

	return (qt == dns.TypeA || qt == dns.TypeAAAA) &&
		(host == applePrivateRelayMaskHost || host == applePrivateRelayMaskH2Host) &&
		reqInfoShouldBlockPrivateRelay(ri)
}

// reqInfoShouldBlockPrivateRelay returns true if Apple Private Relay queries
// should be blocked based on the request information.
func reqInfoShouldBlockPrivateRelay(ri *agd.RequestInfo) (ok bool) {
	if prof := ri.Profile; prof != nil {
		return prof.BlockPrivateRelay
	}

	return ri.FilteringGroup.BlockPrivateRelay
}

// handlePrivateRelay responds to Apple Private Relay queries with an NXDOMAIN
// response.
func (mw *initMw) handlePrivateRelay(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	metrics.DNSSvcApplePrivateRelayRequestsTotal.Inc()

	err = rw.WriteMsg(ctx, req, ri.Messages.NewMsgNXDOMAIN(req))

	return errors.Annotate(err, "writing private relay resp: %w")
}
