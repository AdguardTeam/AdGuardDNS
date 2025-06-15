// Package websvc contains the AdGuard DNS web service.
package websvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/AdguardTeam/golibs/service"
)

// Service is the AdGuard DNS web service.  A nil *Service serves a simple
// plain-text 404 page.
type Service struct {
	logger *slog.Logger

	adultBlockingBPS   *blockPageServer
	generalBlockingBPS *blockPageServer
	safeBrowsingBPS    *blockPageServer

	certValidator CertificateValidator

	dnsCheck       http.Handler
	staticContent  http.Handler
	wellKnownProxy http.Handler

	metrics Metrics

	rootRedirectURL string

	error404 []byte
	error500 []byte

	adultBlocking   []*server
	generalBlocking []*server
	linkedIP        []*server
	nonDoH          []*server
	safeBrowsing    []*server
}

// New returns a new properly initialized *Service.  If c is nil, svc is a nil
// *Service that only serves a simple plain-text 404 page.  The service must be
// refreshed with [Service.Refresh] before use.
func New(c *Config) (svc *Service) {
	if c == nil {
		return nil
	}

	adultBlockingBPS := newBlockPageServer(
		c.AdultBlocking,
		c.Logger,
		c.Metrics,
		ServerGroupAdultBlockingPage,
	)
	generalBlockingBPS := newBlockPageServer(
		c.GeneralBlocking,
		c.Logger,
		c.Metrics,
		ServerGroupGeneralBlockingPage)
	safeBrowsingBPS := newBlockPageServer(
		c.SafeBrowsing,
		c.Logger,
		c.Metrics,
		ServerGroupSafeBrowsingPage,
	)

	svc = &Service{
		logger: c.Logger,

		adultBlockingBPS:   adultBlockingBPS,
		generalBlockingBPS: generalBlockingBPS,
		safeBrowsingBPS:    safeBrowsingBPS,

		certValidator: c.CertificateValidator,

		dnsCheck:      c.DNSCheck,
		staticContent: c.StaticContent,

		metrics: c.Metrics,

		error404: c.Error404,
		error500: c.Error500,

		adultBlocking:   newBlockPageServers(c.Logger, adultBlockingBPS, c.Timeout),
		generalBlocking: newBlockPageServers(c.Logger, generalBlockingBPS, c.Timeout),
		safeBrowsing:    newBlockPageServers(c.Logger, safeBrowsingBPS, c.Timeout),
	}

	if c.RootRedirectURL != nil {
		// Use a string to prevent allocation of a string on every call to the
		// main handler.
		svc.rootRedirectURL = c.RootRedirectURL.String()
	}

	svc.setLinkedIP(c)

	for _, b := range c.NonDoHBind {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupNonDoH)
		h := httputil.Wrap(
			svc,
			httputil.ServerHeaderMiddleware(agdhttp.UserAgent()),
			httputil.NewLogMiddleware(logger, slog.LevelDebug),
		)

		svc.nonDoH = append(svc.nonDoH, newServer(&serverConfig{
			BaseLogger:     logger,
			TLSConf:        b.TLS,
			Handler:        h,
			InitialAddress: b.Address,
			Timeout:        c.Timeout,
		}))
	}

	return svc
}

// setLinkedIP sets the linked-IP and well-known URL proxy handlers.
func (svc *Service) setLinkedIP(c *Config) {
	l := c.LinkedIP
	if l == nil {
		svc.wellKnownProxy = http.NotFoundHandler()

		return
	}

	logger := svc.logger.With(loggerKeyGroup, ServerGroupLinkedIP)
	for _, b := range l.Bind {
		proxyLogger := logger.With("proxy_addr", b.Address)
		h := httputil.Wrap(
			newLinkedIPHandler(&linkedIPHandlerConfig{
				targetURL:     l.TargetURL,
				certValidator: nil,
				errColl:       c.ErrColl,
				proxyLogger:   proxyLogger,
				metrics:       c.Metrics,
				timeout:       c.Timeout,
			}),
			httputil.NewLogMiddleware(logger, slog.LevelDebug),
		)

		svc.linkedIP = append(svc.linkedIP, newServer(&serverConfig{
			BaseLogger:     logger,
			TLSConf:        b.TLS,
			Handler:        h,
			InitialAddress: b.Address,
			Timeout:        c.Timeout,
		}))
	}

	// TODO(a.garipov):  Improve logging.
	wkProxyLogger := svc.logger.With(
		loggerKeyGroup, ServerGroupNonDoH,
		"subgroup", "well_known_proxy",
	)
	svc.wellKnownProxy = httputil.Wrap(
		newLinkedIPHandler(&linkedIPHandlerConfig{
			targetURL:     l.TargetURL,
			certValidator: c.CertificateValidator,
			errColl:       c.ErrColl,
			proxyLogger:   wkProxyLogger,
			metrics:       c.Metrics,
			timeout:       c.Timeout,
		}),
		httputil.NewLogMiddleware(logger, slog.LevelInfo),
	)
}

// type check
var _ service.Interface = (*Service)(nil)

// Start implements the [service.Interface] interface for *Service.  It starts
// serving all endpoints but does not wait for them to actually go online.  svc
// may be nil.  err is always nil; if any endpoint fails to start, it panics.
//
// TODO(a.garipov): Wait for the services to go online.
func (svc *Service) Start(ctx context.Context) (err error) {
	if svc == nil {
		return nil
	}

	svc.logger.InfoContext(ctx, "starting")
	defer svc.logger.InfoContext(ctx, "started")

	for _, srv := range svc.linkedIP {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupLinkedIP)
		go srv.serve(ctx, logger)
	}

	for _, srv := range svc.adultBlocking {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupAdultBlockingPage)
		go srv.serve(ctx, logger)
	}

	for _, srv := range svc.generalBlocking {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupGeneralBlockingPage)
		go srv.serve(ctx, logger)
	}

	for _, srv := range svc.safeBrowsing {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupSafeBrowsingPage)
		go srv.serve(ctx, logger)
	}

	for _, srv := range svc.nonDoH {
		logger := svc.logger.With(loggerKeyGroup, ServerGroupNonDoH)
		go srv.serve(ctx, logger)
	}

	return nil
}

// Shutdown implements the [service.Interface] interface for *Service.  svc may
// be nil.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	if svc == nil {
		return nil
	}

	svc.logger.InfoContext(ctx, "shutting down")
	defer svc.logger.InfoContext(ctx, "shut down")

	serverGroups := container.KeyValues[ServerGroup, []*server]{{
		Key:   ServerGroupLinkedIP,
		Value: svc.linkedIP,
	}, {
		Key:   ServerGroupAdultBlockingPage,
		Value: svc.adultBlocking,
	}, {
		Key:   ServerGroupGeneralBlockingPage,
		Value: svc.generalBlocking,
	}, {
		Key:   ServerGroupSafeBrowsingPage,
		Value: svc.safeBrowsing,
	}, {
		Key:   ServerGroupNonDoH,
		Value: svc.nonDoH,
	}}

	for _, g := range serverGroups {
		err = shutdownServers(ctx, g.Value, g.Key)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}
	}

	return nil
}

// shutdownServers is a helper function that shuts down srvs.
func shutdownServers(ctx context.Context, srvs []*server, g ServerGroup) (err error) {
	var errs []error
	for i, srv := range srvs {
		err = srv.shutdown(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("server group %s: server at index %d: %w", g, i, err))
		}
	}

	return errors.Join(errs...)
}

// type check
var _ service.Refresher = (*Service)(nil)

// Refresh implements the [service.Refresher] interface for *Service.  svc may
// be nil.
func (svc *Service) Refresh(ctx context.Context) (err error) {
	if svc == nil {
		return nil
	}

	svc.logger.InfoContext(ctx, "refresh started")
	defer svc.logger.InfoContext(ctx, "refresh finished")

	servers := []*blockPageServer{
		svc.adultBlockingBPS,
		svc.generalBlockingBPS,
		svc.safeBrowsingBPS,
	}

	var errs []error
	for _, srv := range servers {
		err = srv.Refresh(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("refreshing %s block page server: %w", srv.group, err))
		}
	}

	return errors.Join(errs...)
}

// Handler returns a handler that wraps svc with [httputil.LogMiddleware].
//
// TODO(a.garipov):  Ensure logging in module dnssvc and remove this crutch.
func (svc *Service) Handler() (h http.Handler) {
	// Keep in sync with [New].
	logger := svc.logger.With(loggerKeyGroup, ServerGroupNonDoH)

	return httputil.Wrap(
		svc,
		httputil.ServerHeaderMiddleware(agdhttp.UserAgent()),
		httputil.NewLogMiddleware(logger, slog.LevelDebug),
	)
}
