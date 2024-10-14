// Package debugsvc contains the debug HTTP API of AdGuard DNS.
package debugsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
)

// Service is the HTTP service of AdGuard DNS.  It serves prometheus metrics,
// pprof, health check, DNSDB, and other endpoints.
type Service struct {
	logger    *slog.Logger
	refrHdlr  *refreshHandler
	cacheHdlr *cacheHandler
	dnsDB     http.Handler

	// servers are the servers of this service by their address.  Map entries
	// must not be nil.
	servers map[string]*server
}

// server is a single HTTP server within the AdGuard DNS HTTP service that can
// host multiple handler groups.
type server struct {
	http *http.Server
	name string
}

// Config is the AdGuard DNS HTTP service configuration structure.
type Config struct {
	DNSDBHandler   http.Handler
	Logger         *slog.Logger
	Manager        *agdcache.DefaultManager
	Refreshers     Refreshers
	DNSDBAddr      string
	APIAddr        string
	PprofAddr      string
	PrometheusAddr string
}

// handlerGroup is a semantic alias for names of handler groups.
type handlerGroup = string

// Valid handler groups.
const (
	handlerGroupAPI        handlerGroup = "api"
	handlerGroupDNSDB      handlerGroup = "dnsdb"
	handlerGroupPprof      handlerGroup = "pprof"
	handlerGroupPrometheus handlerGroup = "prometheus"
)

// New returns a new properly initialized *Service.
func New(c *Config) (svc *Service) {
	svc = &Service{
		logger: c.Logger,
		refrHdlr: &refreshHandler{
			refrs: c.Refreshers,
		},
		cacheHdlr: &cacheHandler{
			manager: c.Manager,
		},
		servers: map[string]*server{},
		dnsDB:   c.DNSDBHandler,
	}

	svc.initServers(c)
	svc.route(c)

	return svc
}

// initServers initializes the svc.servers field by adding the required amount
// of servers for the addresses given in the config.
func (svc *Service) initServers(c *Config) {
	groups := container.KeyValues[string, handlerGroup]{{
		Key:   c.APIAddr,
		Value: handlerGroupAPI,
	}, {
		Key:   c.DNSDBAddr,
		Value: handlerGroupDNSDB,
	}, {
		Key:   c.PprofAddr,
		Value: handlerGroupPprof,
	}, {
		Key:   c.PrometheusAddr,
		Value: handlerGroupPrometheus,
	}}

	for _, group := range groups {
		addr := group.Key
		if addr == "" {
			continue
		}

		grpName := group.Value
		srv := svc.servers[addr]
		if srv != nil {
			srv.name += ";" + grpName

			continue
		}

		svc.servers[addr] = &server{
			// #nosec G112 -- Do not set the timeouts, since debug/pprof and
			// similar debug APIs may be busy for a long time.
			http: &http.Server{
				Addr:    addr,
				Handler: http.NewServeMux(),
			},
			name: grpName,
		}
	}
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
		go runServer(ctx, svc.logger, srv)
	}

	return nil
}

// runServer runs one server and panics if there is an unexpected error.  It is
// intended to be used as a goroutine.
func runServer(ctx context.Context, l *slog.Logger, s *server) {
	defer slogutil.RecoverAndExit(ctx, l, osutil.ExitCodeFailure)

	l.InfoContext(ctx, "listening", "name", s.name, "addr", s.http.Addr)

	srv := s.http
	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		panic(fmt.Errorf("server %s: failed listen on %s: %s", s.name, srv.Addr, err))
	}
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

		svc.logger.InfoContext(ctx, "server is shutdown", "name", srv.name)
	}

	svc.logger.InfoContext(ctx, "all servers shutdown", "num", srvNum)

	return nil
}
