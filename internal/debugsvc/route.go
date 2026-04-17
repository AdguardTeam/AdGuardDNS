package debugsvc

import (
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ErrDebugPanic is a default error for panic handler.
const ErrDebugPanic errors.Error = "debug panic"

// Path pattern constants.
const (
	PathPatternDNSDBCSV        = "/dnsdb/csv"
	PathPatternDebugAPICache   = "/debug/api/cache/clear"
	PathPatternDebugAPIGeoIP   = "/debug/api/geoip"
	PathPatternDebugAPIRefresh = "/debug/api/refresh"
	PathPatternDebugPanic      = "/debug/panic"
	PathPatternHealthCheck     = "/health-check"
	PathPatternMetrics         = "/metrics"
)

// Route pattern constants.
const (
	routePatternDNSDBCSV        = http.MethodPost + " " + PathPatternDNSDBCSV
	routePatternDebugAPICache   = http.MethodPost + " " + PathPatternDebugAPICache
	routePatternDebugAPIGeoIP   = http.MethodGet + " " + PathPatternDebugAPIGeoIP
	routePatternDebugAPIRefresh = http.MethodPost + " " + PathPatternDebugAPIRefresh
	routePatternDebugPanic      = http.MethodPost + " " + PathPatternDebugPanic
	routePatternHealthCheck     = http.MethodGet + " " + PathPatternHealthCheck
	routePatternMetrics         = http.MethodGet + " " + PathPatternMetrics
)

// hdlrGrpKey is a handler group argument name for the logger.
const hdlrGrpKey = "hdlr_grp"

// route further initializes the svc.servers field by adding handlers and
// loggers to each server.
func (svc *Service) route(mux *http.ServeMux, gr HandlerGroup) {
	switch gr {
	case HandlerGroupAPI:
		svc.routeAPIGroup(mux)
	case HandlerGroupDNSDB:
		svc.routeDNSPBGroup(mux)
	case HandlerGroupPrometheus:
		svc.routePrometheusGroup(mux)
	case HandlerGroupPprof:
		svc.routePprofGroup(mux)
	default:
		return
	}
}

// routeAPIGroup routes API group related handlers.  mux must not be nil.
func (svc *Service) routeAPIGroup(mux *http.ServeMux) {
	l := svc.logger.With(hdlrGrpKey, HandlerGroupAPI)

	mux.Handle(
		routePatternHealthCheck,
		httputil.Wrap(
			httputil.HealthCheckHandler,
			httputil.NewLogMiddleware(l, slogutil.LevelTrace),
		),
	)

	infoLogMw := httputil.NewLogMiddleware(l, slog.LevelInfo)
	mux.Handle(routePatternDebugAPIRefresh, httputil.Wrap(svc.refrHdlr, infoLogMw))
	mux.Handle(routePatternDebugAPICache, httputil.Wrap(svc.cacheHdlr, infoLogMw))
	mux.Handle(routePatternDebugAPIGeoIP, httputil.Wrap(svc.geoIPHdlr, infoLogMw))

	panicHdlr := httputil.PanicHandler(ErrDebugPanic)
	mux.Handle(routePatternDebugPanic, httputil.Wrap(panicHdlr, infoLogMw))
}

// routeDNSPBGroup route DNSPB group related handlers.  mux must not be nil.
func (svc *Service) routeDNSPBGroup(mux *http.ServeMux) {
	l := svc.logger.With(hdlrGrpKey, HandlerGroupDNSDB)

	mux.Handle(
		routePatternDNSDBCSV,
		httputil.Wrap(
			svc.dnsDB,
			httputil.NewLogMiddleware(l, slog.LevelInfo),
		),
	)
}

// routePprofGroup routes Pprof group related handlers.  mux must not be nil.
func (svc *Service) routePprofGroup(mux *http.ServeMux) {
	l := svc.logger.With(hdlrGrpKey, HandlerGroupPprof)
	mw := httputil.NewLogMiddleware(l, slog.LevelDebug)

	routeWithMw := httputil.RouterFunc(func(pattern string, h http.Handler) {
		mux.Handle(pattern, httputil.Wrap(h, mw))
	})

	httputil.RoutePprof(routeWithMw)
}

// routePrometheusGroup routes Prometheus related handlers.
// mux must not be nil.
func (svc *Service) routePrometheusGroup(mux *http.ServeMux) {
	l := svc.logger.With(hdlrGrpKey, HandlerGroupPrometheus)

	mux.Handle(
		routePatternMetrics,
		httputil.Wrap(
			promhttp.Handler(),
			httputil.NewLogMiddleware(l, slogutil.LevelTrace)),
	)
}
