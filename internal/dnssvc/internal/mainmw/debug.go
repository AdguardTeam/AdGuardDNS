package mainmw

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Debug header name constants.
const (
	hdrNameResType     = "res-type"
	hdrNameRuleListID  = "rule-list-id"
	hdrNameRule        = "rule"
	hdrNameClientIP    = "client-ip"
	hdrNameServerIP    = "server-ip"
	hdrNameDeviceID    = "device-id"
	hdrNameProfileID   = "profile-id"
	hdrNameCountry     = "country"
	hdrNameASN         = "asn"
	hdrNameSubdivision = "subdivision"
	hdrNameHost        = "adguard-dns.com."
)

// writeDebugResponse writes the debug response to rw.
func (mw *Middleware) writeDebugResponse(
	ctx context.Context,
	fctx *filteringContext,
	rw dnsserver.ResponseWriter,
) (err error) {
	defer func() { err = errors.Annotate(err, "debug: %w") }()

	resp := fctx.filteredResponse
	resp.Question[0].Qclass = dns.ClassCHAOS

	debugReq := mw.cloner.Clone(fctx.originalRequest)
	debugReq.Question[0].Qclass = dns.ClassCHAOS
	debugReq.Question[0].Qtype = dns.TypeTXT

	rAddr := rw.RemoteAddr()
	cliIP, _ := netutil.IPAndPortFromAddr(rAddr)

	setQuestionName(debugReq, "", hdrNameClientIP)
	err = mw.messages.AppendDebugExtra(debugReq, resp, cliIP.String())
	if err != nil {
		return fmt.Errorf("adding %s extra: %w", hdrNameClientIP, err)
	}

	lAddr := rw.LocalAddr()
	localIP, _ := netutil.IPAndPortFromAddr(lAddr)

	setQuestionName(debugReq, "", hdrNameServerIP)
	err = mw.messages.AppendDebugExtra(debugReq, resp, localIP.String())
	if err != nil {
		return fmt.Errorf("adding %s extra: %w", hdrNameServerIP, err)
	}

	err = mw.appendDebugExtraFromContext(ctx, debugReq, resp)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if fctx.requestResult == nil {
		err = mw.debugResponse(debugReq, resp, fctx.responseResult, "resp")
	} else {
		err = mw.debugResponse(debugReq, resp, fctx.requestResult, "req")
	}
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return rw.WriteMsg(ctx, fctx.originalRequest, resp)
}

// appendDebugExtraFromContext appends debug extra records that we can get from
// the context.
func (mw *Middleware) appendDebugExtraFromContext(
	ctx context.Context,
	debugReq *dns.Msg,
	resp *dns.Msg,
) (err error) {
	ri := agd.MustRequestInfoFromContext(ctx)
	if d := ri.Device; d != nil {
		setQuestionName(debugReq, "", hdrNameDeviceID)
		err = mw.messages.AppendDebugExtra(debugReq, resp, string(d.ID))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameDeviceID, err)
		}
	}

	if p := ri.Profile; p != nil {
		setQuestionName(debugReq, "", hdrNameProfileID)
		err = mw.messages.AppendDebugExtra(debugReq, resp, string(p.ID))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameProfileID, err)
		}
	}

	if loc := ri.Location; loc != nil {
		err = mw.appendDebugExtraFromLocation(loc, debugReq, resp)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}
	}

	return nil
}

// appendDebugExtraFromLocation adds debug info to response got from request
// info location.  loc should not be nil.
func (mw *Middleware) appendDebugExtraFromLocation(
	loc *geoip.Location,
	debugReq *dns.Msg,
	resp *dns.Msg,
) (err error) {
	setQuestionName(debugReq, "", hdrNameCountry)
	err = mw.messages.AppendDebugExtra(debugReq, resp, string(loc.Country))
	if err != nil {
		return fmt.Errorf("adding %s extra: %w", hdrNameCountry, err)
	}

	setQuestionName(debugReq, "", hdrNameASN)
	err = mw.messages.AppendDebugExtra(debugReq, resp, strconv.FormatUint(uint64(loc.ASN), 10))
	if err != nil {
		return fmt.Errorf("adding %s extra: %w", hdrNameASN, err)
	}

	if subdivision := loc.TopSubdivision; subdivision != "" {
		setQuestionName(debugReq, "", hdrNameSubdivision)
		err = mw.messages.AppendDebugExtra(debugReq, resp, subdivision)
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameSubdivision, err)
		}
	}

	return nil
}

// debugResponse forms a debug response.
func (mw *Middleware) debugResponse(
	req *dns.Msg,
	resp *dns.Msg,
	fltRes filter.Result,
	applyTo string,
) (err error) {
	if fltRes == nil {
		setQuestionName(req, applyTo, hdrNameResType)
		err = mw.messages.AppendDebugExtra(req, resp, "normal")

		return errors.Annotate(err, "adding %s extra: %w", hdrNameProfileID)
	}

	fltID, rule := fltRes.MatchedRule()
	var state string
	switch fltRes.(type) {
	case *filter.ResultAllowed:
		state = "allowed"
	case *filter.ResultBlocked:
		state = "blocked"
	case *filter.ResultModifiedResponse, *filter.ResultModifiedRequest:
		state = "modified"
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "fltRes",
			Message: fmt.Sprintf("unexpected type %T", fltRes),
		})
	}

	return mw.addDebugExtraFromFiltering(req, resp, state, string(rule), string(fltID), applyTo)
}

// addDebugExtraFromFiltering adds to response debug info from filtering meta.
func (mw *Middleware) addDebugExtraFromFiltering(
	req *dns.Msg,
	resp *dns.Msg,
	state string,
	rule string,
	ruleID string,
	applyTo string,
) (err error) {
	setQuestionName(req, applyTo, hdrNameResType)
	err = mw.messages.AppendDebugExtra(req, resp, state)
	if err != nil {
		return fmt.Errorf(
			"adding %s debug extra for %s response: %w",
			hdrNameResType,
			state,
			err,
		)
	}

	setQuestionName(req, applyTo, hdrNameRule)
	err = mw.messages.AppendDebugExtra(req, resp, rule)
	if err != nil {
		return fmt.Errorf("adding %s debug extra: %w", hdrNameRule, err)
	}

	setQuestionName(req, applyTo, hdrNameRuleListID)
	err = mw.messages.AppendDebugExtra(req, resp, ruleID)
	if err != nil {
		return fmt.Errorf("adding %s debug extra: %w", hdrNameRuleListID, err)
	}

	return nil
}

// setQuestionName sets the question name of the request with suffix and prefix.
func setQuestionName(req *dns.Msg, prefix, suffix string) {
	var strs []string
	if prefix == "" {
		strs = []string{suffix, hdrNameHost}
	} else {
		strs = []string{prefix, suffix, hdrNameHost}
	}

	req.Question[0].Name = strings.Join(strs, ".")
}
