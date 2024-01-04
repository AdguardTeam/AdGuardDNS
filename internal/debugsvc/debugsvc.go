// Package debugsvc contains the debug HTTP API of AdGuard DNS.
package debugsvc

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/pprofutil"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Service is the HTTP service of AdGuard DNS.  It serves prometheus metrics,
// pprof, health check, DNSDB, and other endpoints..
type Service struct {
	servers map[string]*server
	dnsDB   http.Handler
}

// Config is the AdGuard DNS HTTP service configuration structure.
type Config struct {
	DNSDBAddr    string
	DNSDBHandler http.Handler

	HealthAddr     string
	PprofAddr      string
	PrometheusAddr string
}

// New returns a new properly initialized *Service.
func New(c *Config) (svc *Service) {
	svc = &Service{
		servers: make(map[string]*server),
		dnsDB:   c.DNSDBHandler,
	}

	svc.addServer(c.DNSDBAddr, "dnsdb")
	svc.addServer(c.PrometheusAddr, "prometheus")
	svc.addServer(c.PprofAddr, "pprof")

	// The health-check server causes panic if it doesn't start because the
	// server is needed to check if the dns server is active.
	svc.addServer(c.HealthAddr, "health-check")

	return svc
}

// server is a single server within the AdGuard DNS HTTP service.
type server struct {
	http *http.Server
	name string
}

// startServer starts one server and panics if there is an unexpected error.
func startServer(s *server) {
	defer log.OnPanicAndExit("startServer", 1)

	log.Info("debugsvc: %s: listen on %s", s.name, s.http.Addr)

	srv := s.http
	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		panic(fmt.Errorf("%s: failed listen on %s: %s", srv.Addr, s.name, err))
	}
}

// type check
var _ agdservice.Interface = (*Service)(nil)

// Start implements the [agdservice.Interface] interface for *Service.  It
// starts serving all endpoints.  err is always nil, if any endpoint fails to
// start, it panics.
func (svc *Service) Start(_ context.Context) (err error) {
	for _, srv := range svc.servers {
		go startServer(srv)
	}

	return nil
}

// Shutdown implements the [agdservice.Interface] interface for *Service.  It
// stops serving all endpoints.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	srvNum := 0
	for _, srv := range svc.servers {
		err = srv.http.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("server %s shutdown: %w", srv.name, err)
		}

		srvNum++

		log.Info("debugsvc: %s: server is shutdown", srv.name)
	}

	log.Info("debugsvc: servers shutdown: %d", srvNum)

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
				ErrorLog: log.StdLog("debugsvc", log.DEBUG),
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
	case "dnsdb":
		svc.dnsDBMux(mux)
	case "health-check":
		healthMux(mux)
	case "pprof":
		pprofutil.RoutePprof(mux)
	case "prometheus":
		promMux(mux)
	default:
		panic(fmt.Errorf("debugsvc: could not find mux for service %q", serviceName))
	}
}

// dnsDBMux adds the DNSDB CSV dump handler to mux.
func (svc *Service) dnsDBMux(mux *http.ServeMux) {
	mux.Handle("/dnsdb/csv", svc.dnsDB)
}

// healthMux adds handler func to the mux from args for the health check service.
func healthMux(mux *http.ServeMux) {
	mux.HandleFunc(
		"/health-check",
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "OK")
		},
	)
}

// promMux adds handler func to the mux from args for the prometheus service.
func promMux(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
