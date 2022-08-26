package dnssvc

import (
	"context"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Middlewares

// Main DNS Service Middleware

// Wrap implements the dnsserver.Middleware interface for *Service.
func (svc *Service) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		isDebug := req.Question[0].Qclass == dns.ClassCHAOS
		if isDebug {
			req.Question[0].Qclass = dns.ClassINET
		}

		reqID, _ := agd.RequestIDFromContext(ctx)
		raddr := rw.RemoteAddr()
		optlog.Debug2("processing request %q from %s", reqID, raddr)
		defer optlog.Debug2("finished processing request %q from %s", reqID, raddr)

		// Assume that the cache is always hot and that we can always send the
		// request and filter it out along with the response later if we need
		// it.
		nwrw := makeNonWriter(rw)
		err = h.ServeDNS(ctx, nwrw, req)
		if err != nil {
			return err
		}

		ri := agd.MustRequestInfoFromContext(ctx)
		origResp := nwrw.Msg()
		reqRes, respRes := svc.filterQuery(ctx, req, origResp, ri)

		if isDebug {
			return svc.writeDebugResponse(ctx, rw, req, origResp, reqRes, respRes)
		}

		resp, err := writeFilteredResp(ctx, ri, rw, req, origResp, reqRes, respRes)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}

		svc.recordQueryInfo(ctx, req, resp, origResp, ri, reqRes, respRes)

		return nil
	}

	return dnsserver.HandlerFunc(f)
}

// makeNonWriter makes rw a *dnsserver.NonWriterResponseWriter unless it already
// is one, in which case it just returns it.
func makeNonWriter(rw dnsserver.ResponseWriter) (nwrw *dnsserver.NonWriterResponseWriter) {
	nwrw, ok := rw.(*dnsserver.NonWriterResponseWriter)
	if ok {
		return nwrw
	}

	return dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
}

// filterQuery is a wrapper for f.FilterRequest and f.FilterResponse that treats
// filtering errors non-critical.  It also records filtering metrics.
func (svc *Service) filterQuery(
	ctx context.Context,
	req *dns.Msg,
	origResp *dns.Msg,
	ri *agd.RequestInfo,
) (reqRes, respRes filter.Result) {
	start := time.Now()
	defer func() {
		reportMetrics(ri, reqRes, respRes, time.Since(start))
	}()

	f := svc.fltStrg.FilterFromContext(ctx, ri)
	reqRes, err := f.FilterRequest(ctx, req, ri)
	if err != nil {
		svc.reportf(ctx, "filtering request: %w", err)
	}

	respRes, err = f.FilterResponse(ctx, origResp, ri)
	if err != nil {
		svc.reportf(ctx, "dnssvc: filtering original response: %w", err)
	}

	return reqRes, respRes
}

// reportMetrics extracts filtering metrics data from the context and reports it
// to Prometheus.
func reportMetrics(
	ri *agd.RequestInfo,
	reqRes filter.Result,
	respRes filter.Result,
	elapsedFiltering time.Duration,
) {
	var ctry, cont string
	asn := "0"
	if l := ri.Location; l != nil {
		ctry, cont = string(l.Country), string(l.Continent)
		asn = strconv.FormatUint(uint64(l.ASN), 10)
	}

	metrics.DNSSvcRequestByCountryTotal.With(prometheus.Labels{
		"country":   ctry,
		"continent": cont,
	}).Inc()
	metrics.DNSSvcRequestByASNTotal.With(prometheus.Labels{
		"country": ctry,
		"asn":     asn,
	}).Inc()

	id, _, _ := filteringData(reqRes, respRes)
	metrics.DNSSvcRequestByFilterTotal.With(prometheus.Labels{
		"filter":    string(id),
		"anonymous": metrics.BoolString(ri.Profile == nil),
	}).Inc()

	metrics.DNSSvcFilteringDuration.Observe(elapsedFiltering.Seconds())
	metrics.DNSSvcUsersCountUpdate(ri.RemoteIP)
}

// reportf is a helper method for reporting non-critical errors.
func (svc *Service) reportf(ctx context.Context, format string, args ...any) {
	agd.Collectf(ctx, svc.errColl, "dnssvc: "+format, args...)
}
