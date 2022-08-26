package dnssvc

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Debug header name constants.
const (
	hdrNameResType    = "res-type"
	hdrNameRuleListID = "rule-list-id"
	hdrNameRule       = "rule"
	hdrNameClientIP   = "client-ip"
	hdrNameDeviceID   = "device-id"
	hdrNameProfileID  = "profile-id"
	hdrNameCountry    = "country"
	hdrNameASN        = "asn"
	hdrNameHost       = "adguard-dns.com."
)

// writeDebugResponse writes the debug response to rw.
func (svc *Service) writeDebugResponse(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	resp *dns.Msg,
	reqRes filter.Result,
	respRes filter.Result,
) (err error) {
	defer func() { err = errors.Annotate(err, "debug: %w") }()

	resp.Question[0].Qclass = dns.ClassCHAOS

	debugReq := dnsmsg.Clone(req)
	debugReq.Question[0].Qclass = dns.ClassCHAOS
	debugReq.Question[0].Qtype = dns.TypeTXT

	rAddr := rw.RemoteAddr()
	cliIP, _ := netutil.IPAndPortFromAddr(rAddr)

	setQuestionName(debugReq, "", hdrNameClientIP)
	err = svc.messages.AppendDebugExtra(debugReq, resp, cliIP.String())
	if err != nil {
		return fmt.Errorf("adding %s extra: %w", hdrNameClientIP, err)
	}

	err = svc.appendDebugExtraFromContext(ctx, debugReq, resp)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if reqRes == nil {
		err = svc.debugResponse(debugReq, resp, respRes, "resp")
	} else {
		err = svc.debugResponse(debugReq, resp, reqRes, "req")
	}
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return rw.WriteMsg(ctx, req, resp)
}

// appendDebugExtraFromContext appends debug extra records that we can get from
// the context.
func (svc *Service) appendDebugExtraFromContext(
	ctx context.Context,
	debugReq *dns.Msg,
	resp *dns.Msg,
) (err error) {
	ri := agd.MustRequestInfoFromContext(ctx)
	if d := ri.Device; d != nil {
		setQuestionName(debugReq, "", hdrNameDeviceID)
		err = svc.messages.AppendDebugExtra(debugReq, resp, string(d.ID))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameDeviceID, err)
		}
	}

	if p := ri.Profile; p != nil {
		setQuestionName(debugReq, "", hdrNameProfileID)
		err = svc.messages.AppendDebugExtra(debugReq, resp, string(p.ID))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameProfileID, err)
		}
	}

	if d := ri.Location; d != nil {
		setQuestionName(debugReq, "", hdrNameCountry)
		err = svc.messages.AppendDebugExtra(debugReq, resp, string(d.Country))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameCountry, err)
		}

		setQuestionName(debugReq, "", hdrNameASN)
		err = svc.messages.AppendDebugExtra(debugReq, resp, strconv.FormatUint(uint64(d.ASN), 10))
		if err != nil {
			return fmt.Errorf("adding %s extra: %w", hdrNameASN, err)
		}
	}

	return nil
}

// debugResponse forms a debug response.
func (svc *Service) debugResponse(
	req *dns.Msg,
	resp *dns.Msg,
	fltRes filter.Result,
	applyTo string,
) (err error) {
	if fltRes == nil {
		setQuestionName(req, applyTo, hdrNameResType)
		err = svc.messages.AppendDebugExtra(req, resp, "normal")

		return errors.Annotate(err, "adding %s extra: %w", hdrNameProfileID)
	}

	fltID, rule := fltRes.MatchedRule()
	var state string
	switch fltRes.(type) {
	case *filter.ResultAllowed:
		state = "allowed"
	case *filter.ResultBlocked:
		state = "blocked"
	case *filter.ResultModified:
		state = "modified"
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "fltRes",
			Message: fmt.Sprintf("unexpected type %T", fltRes),
		})
	}

	return svc.addDebugExtraFromFiltering(req, resp, state, string(rule), string(fltID), applyTo)
}

// addDebugExtraFromFiltering adds to response debug info from filtering meta.
func (svc *Service) addDebugExtraFromFiltering(
	req *dns.Msg,
	resp *dns.Msg,
	state string,
	rule string,
	ruleID string,
	applyTo string,
) (err error) {
	setQuestionName(req, applyTo, hdrNameResType)
	err = svc.messages.AppendDebugExtra(req, resp, state)
	if err != nil {
		return fmt.Errorf(
			"adding %s debug extra for %s response: %w",
			hdrNameResType,
			state,
			err,
		)
	}

	setQuestionName(req, applyTo, hdrNameRule)
	err = svc.messages.AppendDebugExtra(req, resp, rule)
	if err != nil {
		return fmt.Errorf("adding %s debug extra: %w", hdrNameRule, err)
	}

	setQuestionName(req, applyTo, hdrNameRuleListID)
	err = svc.messages.AppendDebugExtra(req, resp, ruleID)
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
