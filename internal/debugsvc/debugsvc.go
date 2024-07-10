// Package debugsvc contains the debug HTTP API of AdGuard DNS.
package debugsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/pprofutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Service is the HTTP service of AdGuard DNS.  It serves prometheus metrics,
// pprof, health check, DNSDB, and other endpoints..
type Service struct {
	log      *slog.Logger
	refrHdlr *refreshHandler
	dnsDB    http.Handler
	servers  map[string]*server
}

// Config is the AdGuard DNS HTTP service configuration structure.
type Config struct {
	Logger *slog.Logger

	DNSDBAddr    string
	DNSDBHandler http.Handler

	Refreshers Refreshers

	// TODO(a.garipov):  Consider using one address and removing addServer
	// logic.

	APIAddr        string
	PprofAddr      string
	PrometheusAddr string
}

// New returns a new properly initialized *Service.
func New(c *Config) (svc *Service) {
	svc = &Service{
		log: c.Logger,
		refrHdlr: &refreshHandler{
			refrs: c.Refreshers,
		},
		servers: make(map[string]*server),
		dnsDB:   c.DNSDBHandler,
	}

	svc.addServer(c.DNSDBAddr, "dnsdb")
	svc.addServer(c.PrometheusAddr, "prometheus")
	svc.addServer(c.PprofAddr, "pprof")

	// The health-check and API server causes panic if it doesn't start because
	// the server is needed to check if the dns server is active.
	svc.addServer(c.APIAddr, "api")

	return svc
}

// server is a single server within the AdGuard DNS HTTP service.
type server struct {
	http *http.Server
	name string
}

// startServer starts one server and panics if there is an unexpected error.
func startServer(ctx context.Context, l *slog.Logger, s *server) {
	defer recoverAndExit(ctx, l)

	l.Info("listening", "name", s.name, "addr", s.http.Addr)

	srv := s.http
	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		panic(fmt.Errorf("%s: failed listen on %s: %s", srv.Addr, s.name, err))
	}
}

// recoverAndExit recovers a panic, logs it using l, and then exits with
// [osutil.ExitCodeFailure].
//
// TODO(a.garipov):  Move to golibs.
func recoverAndExit(ctx context.Context, l *slog.Logger) {
	v := recover()
	if v == nil {
		return
	}

	var args []any
	if err, ok := v.(error); ok {
		args = []any{slogutil.KeyError, err}
	} else {
		args = []any{"value", v}
	}

	l.ErrorContext(ctx, "recovered from panic", args...)
	slogutil.PrintStack(ctx, l, slog.LevelError)

	os.Exit(osutil.ExitCodeFailure)
}

// type check
var _ service.Interface = (*Service)(nil)

// Start implements the [service.Interface] interface for *Service.  It starts
// serving all endpoints but does not wait for them to actually go online.  err
// is always nil, if any endpoint fails to start, it panics.
//
// TODO(a.garipov): Wait for the services to go online.
//
// TODO(a.garipov): Use the context for cancelation.
func (svc *Service) Start(ctx context.Context) (err error) {
	for _, srv := range svc.servers {
		go startServer(ctx, svc.log, srv)
	}

	return nil
}

// Shutdown implements the [service.Interface] interface for *Service.  It stops
// serving all endpoints.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	srvNum := 0
	for _, srv := range svc.servers {
		err = srv.http.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("server %s shutdown: %w", srv.name, err)
		}

		srvNum++

		svc.log.Info("server is shutdown", "name", srv.name)
	}

	svc.log.Info("all servers shutdown", "num", srvNum)

	return nil
}

// addServer adds the named handler to the service, creating a new server
// listening on a different address if necessary.  If addr is empty, the service
// isn't created.
func (svc *Service) addServer(addr, name string) {
	if addr == "" {
		return
	}

	var mux *http.ServeMux

	srv, ok := svc.servers[addr]
	if !ok {
		mux = http.NewServeMux()
		svc.addHandler(name, mux)

		svc.servers[addr] = &server{
			// #nosec G112 -- Do not set the timeouts, since debug/pprof and
			// similar debug APIs may be busy for a long time.
			http: &http.Server{
				Addr:     addr,
				Handler:  mux,
				ErrorLog: slog.NewLogLogger(svc.log.Handler(), slog.LevelDebug),
			},
			name: name,
		}

		return
	}

	mux = srv.http.Handler.(*http.ServeMux)
	svc.addHandler(name, mux)
	srv.name += ";" + name
}

// addHandler func returns the resMux that combine with the mux from args.
func (svc *Service) addHandler(serviceName string, mux *http.ServeMux) {
	switch serviceName {
	case "api":
		svc.apiMux(mux)
	case "dnsdb":
		svc.dnsDBMux(mux)
	case "pprof":
		// TODO(a.garipov): Find ways to wrap pprof handlers.
		pprofutil.RoutePprof(mux)
	case "prometheus":
		svc.promMux(mux)
	default:
		panic(fmt.Errorf("debugsvc: could not find mux for service %q", serviceName))
	}
}

// apiMux adds the health-check and other debug API handlers to mux.
func (svc *Service) apiMux(mux *http.ServeMux) {
	mux.Handle("GET /health-check", svc.middleware(
		http.HandlerFunc(serveHealthCheck),
		slog.LevelDebug,
	))
	mux.Handle("POST /debug/api/refresh", svc.middleware(svc.refrHdlr, slog.LevelInfo))
}

// dnsDBMux adds the DNSDB CSV dump handler to mux.
//
// TODO(a.garipov):  Tests.
func (svc *Service) dnsDBMux(mux *http.ServeMux) {
	mux.Handle("POST /dnsdb/csv", svc.middleware(svc.dnsDB, slog.LevelInfo))
}

// promMux adds the prometheus service handler to mux.
func (svc *Service) promMux(mux *http.ServeMux) {
	mux.Handle("GET /metrics", svc.middleware(promhttp.Handler(), slog.LevelDebug))
}
