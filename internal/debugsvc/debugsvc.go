// Package debugsvc contains the debug HTTP API of AdGuard DNS.
//
// TODO(a.garipov):  Add standard or custom metrics.
package debugsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
)

// Service is the HTTP service of AdGuard DNS.  It serves prometheus metrics,
// pprof, health check, DNSDB, and other endpoints.
type Service struct {
	logger    *slog.Logger
	refrHdlr  *refreshHandler
	cacheHdlr *cacheHandler
	geoIPHdlr *geoIPHandler
	dnsDB     http.Handler

	// servers are the servers of this service by their address.  Map entries
	// must not be nil.
	servers map[string]*server
}

// server is a single HTTP server within the AdGuard DNS HTTP service that can
// host multiple handler groups.
type server struct {
	srv  *httputil.Server
	name string
}

// Config is the AdGuard DNS HTTP service configuration structure.
type Config struct {
	DNSDBHandler http.Handler

	// GeoIP is the GeoIP database used to detect geographic data about IP
	// addresses in requests and responses.  It must not be nil.
	GeoIP geoip.Interface

	Logger         *slog.Logger
	Manager        *agdcache.DefaultManager
	Refreshers     Refreshers
	DNSDBAddr      netip.AddrPort
	APIAddr        netip.AddrPort
	PprofAddr      netip.AddrPort
	PrometheusAddr netip.AddrPort
}

// HandlerGroup is a semantic alias for names of handler groups.
type HandlerGroup = string

// Valid handler groups.
const (
	HandlerGroupAPI        HandlerGroup = "api"
	HandlerGroupDNSDB      HandlerGroup = "dnsdb"
	HandlerGroupPprof      HandlerGroup = "pprof"
	HandlerGroupPrometheus HandlerGroup = "prometheus"
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
		geoIPHdlr: &geoIPHandler{
			geoIP: c.GeoIP,
		},
		servers: map[string]*server{},
		dnsDB:   c.DNSDBHandler,
	}

	groups := container.KeyValues[netip.AddrPort, HandlerGroup]{{
		Key:   c.APIAddr,
		Value: HandlerGroupAPI,
	}, {
		Key:   c.DNSDBAddr,
		Value: HandlerGroupDNSDB,
	}, {
		Key:   c.PprofAddr,
		Value: HandlerGroupPprof,
	}, {
		Key:   c.PrometheusAddr,
		Value: HandlerGroupPrometheus,
	}}

	svc.setupGroups(groups)

	return svc
}

// setupGroups setups handler groups and initializes servers for handler
// groups.  groups must not be nil.
func (svc *Service) setupGroups(groups container.KeyValues[netip.AddrPort, HandlerGroup]) {
	addrToHandlers := make(map[netip.AddrPort][]HandlerGroup)

	for _, group := range groups {
		addr := group.Key

		if addr == (netip.AddrPort{}) {
			continue
		}

		_, ok := addrToHandlers[addr]
		if !ok {
			addrToHandlers[addr] = []HandlerGroup(nil)
		}

		addrToHandlers[addr] = append(addrToHandlers[addr], group.Value)
	}

	for addr, handlers := range addrToHandlers {
		svc.initServer(addr, handlers)
	}
}

// initServer inits a new server.  It setups mux, middleware and handlers for
// the server.
func (svc *Service) initServer(addr netip.AddrPort, handlerGroup []HandlerGroup) {
	addrStr := addr.String()
	mux := http.NewServeMux()

	for _, groupName := range handlerGroup {
		svc.route(mux, groupName)

		srv := svc.servers[addrStr]
		if srv != nil {
			srv.name += ";" + groupName

			continue
		}

		srvHdrMw := httputil.ServerHeaderMiddleware(agdhttp.UserAgent())
		reqIDMw := httputil.NewRequestIDMiddleware()
		handler := httputil.Wrap(mux, srvHdrMw, reqIDMw)
		l := svc.logger.With("name", groupName)

		// #nosec G112 -- Do not set the timeouts, since debug/pprof and
		// similar debug APIs may be busy for a long time.
		httpSrv := httputil.NewServer(&httputil.ServerConfig{
			BaseLogger:     l,
			InitialAddress: addr,
			Server: &http.Server{
				Addr:    addrStr,
				Handler: handler,
			},
		})

		svc.servers[addrStr] = &server{
			srv:  httpSrv,
			name: groupName,
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
// TODO(a.garipov): Use the context for cancellation.
func (svc *Service) Start(ctx context.Context) (err error) {
	for _, srv := range svc.servers {
		go runServer(ctx, svc.logger, srv)
	}

	return nil
}

// runServer runs one server and panics if there is an unexpected error.  It is
// intended to be used as a goroutine.
func runServer(ctx context.Context, l *slog.Logger, s *server) {
	l.InfoContext(ctx, "listening", "name", s.name)

	srv := s.srv
	go func() {
		defer slogutil.RecoverAndExit(ctx, l, osutil.ExitCodeFailure)

		err := srv.Start(ctx)
		if err != nil {
			panic(fmt.Errorf("server %s: failed listen on %s: %w", s.name, srv.LocalAddr(), err))
		}
	}()
}

// Shutdown implements the [service.Interface] interface for *Service.  It stops
// serving all endpoints.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	srvNum := 0
	for _, s := range svc.servers {
		err = s.srv.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("server %s shutdown: %w", s.name, err)
		}

		srvNum++

		svc.logger.InfoContext(ctx, "server is shutdown", "name", s.name)
	}

	svc.logger.InfoContext(ctx, "all servers shutdown", "num", srvNum)

	return nil
}
