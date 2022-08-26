// Package websvc contains the AdGuard DNS web service.
package websvc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Config is the AdGuard DNS web service configuration structure.
type Config struct {
	// SafeBrowsing is the optional safe browsing block page web server.
	SafeBrowsing *BlockPageServer

	// AdultBlocking is the optional adult blocking block page web server.
	AdultBlocking *BlockPageServer

	// LinkedIP is the optional linked IP web server.
	LinkedIP *LinkedIPServer

	// LinkedIPBackendURL is the URL to which linked IP API requests are
	// proxied.
	LinkedIPBackendURL *url.URL

	// RootRedirectURL is the URL to which root HTTP requests are redirected.
	// If not set, these requests are responded with a 404 page.
	RootRedirectURL *url.URL

	// StaticContent is the content that is served statically at the given
	// paths.
	StaticContent StaticContent

	// DNSCheck is the HTTP handler for DNS checks.
	DNSCheck http.Handler

	// ErrColl is used to collect linked IP proxy errors and other errors.
	ErrColl agd.ErrorCollector

	// Error404 is the content of the HTML page for the 404 status.  If not set,
	// a simple plain text 404 response is served.
	Error404 []byte

	// Error500 is the content of the HTML page for the 500 status.  If not set,
	// a simple plain text 500 response is served.
	Error500 []byte

	// NonDoHBind are the bind addresses and optional TLS configuration for the
	// web service in addition to the ones in the DNS-over-HTTPS handlers.
	NonDoHBind []*BindData

	// Timeout is the timeout for all server operations.
	Timeout time.Duration
}

// LinkedIPServer is the linked IP server configuration.
type LinkedIPServer struct {
	// Bind are the addresses on which to serve the linked IP API.
	Bind []*BindData
}

// BlockPageServer is the safe browsing or adult blocking block page server
// configuration.
type BlockPageServer struct {
	// Content is the content of the HTML block page.
	Content []byte

	// Bind are the addresses on which to serve the block page.
	Bind []*BindData
}

// BindData is data for binding one HTTP server to an address.
type BindData struct {
	// TLS is the optional TLS configuration.
	TLS *tls.Config

	// Address is the binding address.
	Address netip.AddrPort
}

// Service is the AdGuard DNS web service.  A nil *Service serves a simple
// plain-text 404 page.
type Service struct {
	rootRedirectURL string

	staticContent StaticContent

	dnsCheck http.Handler

	error404 []byte
	error500 []byte

	linkedIP      []*http.Server
	adultBlocking []*http.Server
	safeBrowsing  []*http.Server
	nonDoH        []*http.Server
}

// New returns a new properly initialized *Service.  If c is nil, svc is a nil
// *Service that only serves a simple plain-text 404 page.
func New(c *Config) (svc *Service) {
	if c == nil {
		return nil
	}

	svc = &Service{
		staticContent: c.StaticContent,

		dnsCheck: c.DNSCheck,

		error404: c.Error404,
		error500: c.Error500,

		adultBlocking: blockPageServers(c.AdultBlocking, "adult blocking", c.Timeout),
		safeBrowsing:  blockPageServers(c.SafeBrowsing, "safe browsing", c.Timeout),
	}

	if c.RootRedirectURL != nil {
		// Use a string to prevent allocation of a string on every call to the
		// main handler.
		svc.rootRedirectURL = c.RootRedirectURL.String()
	}

	if l := c.LinkedIP; l != nil {
		for _, b := range l.Bind {
			addr := b.Address.String()
			h := linkedIPHandler(c.LinkedIPBackendURL, c.ErrColl, addr, c.Timeout)
			errLog := log.StdLog(fmt.Sprintf("websvc: linked ip: %s", addr), log.DEBUG)
			svc.linkedIP = append(svc.linkedIP, &http.Server{
				Addr:              addr,
				Handler:           h,
				TLSConfig:         b.TLS,
				ErrorLog:          errLog,
				ReadTimeout:       c.Timeout,
				WriteTimeout:      c.Timeout,
				IdleTimeout:       c.Timeout,
				ReadHeaderTimeout: c.Timeout,
			})
		}
	}

	for _, b := range c.NonDoHBind {
		addr := b.Address.String()
		errLog := log.StdLog(fmt.Sprintf("websvc: non-doh: %s", addr), log.DEBUG)
		svc.nonDoH = append(svc.nonDoH, &http.Server{
			Addr:              addr,
			Handler:           svc,
			TLSConfig:         b.TLS,
			ErrorLog:          errLog,
			ReadTimeout:       c.Timeout,
			WriteTimeout:      c.Timeout,
			IdleTimeout:       c.Timeout,
			ReadHeaderTimeout: c.Timeout,
		})
	}

	return svc
}

// blockPageServers is a helper function that converts a *BlockPageServer into
// HTTP servers.
func blockPageServers(
	srv *BlockPageServer,
	name string,
	timeout time.Duration,
) (srvs []*http.Server) {
	if srv == nil {
		return nil
	}

	h := safeBrowsingHandler(name, srv.Content)
	for _, b := range srv.Bind {
		addr := b.Address.String()
		errLog := log.StdLog(fmt.Sprintf("websvc: %s: %s", name, addr), log.DEBUG)
		srvs = append(srvs, &http.Server{
			Addr:              addr,
			Handler:           h,
			TLSConfig:         b.TLS,
			ErrorLog:          errLog,
			ReadTimeout:       timeout,
			WriteTimeout:      timeout,
			IdleTimeout:       timeout,
			ReadHeaderTimeout: timeout,
		})
	}

	return srvs
}

// type check
var _ agd.Service = (*Service)(nil)

// Start implements the agd.Service interface for *Service.  svc may be nil.  It
// panics if one of the servers could not start.
func (svc *Service) Start() (err error) {
	if svc == nil {
		return nil
	}

	for _, srv := range svc.linkedIP {
		go mustStartServer(srv)

		log.Info("websvc: linked ip %s: server is started", srv.Addr)
	}

	for _, srv := range svc.safeBrowsing {
		go mustStartServer(srv)

		log.Info("websvc: safe browsing %s: server is started", srv.Addr)
	}

	for _, srv := range svc.adultBlocking {
		go mustStartServer(srv)

		log.Info("websvc: adult blocking %s: server is started", srv.Addr)
	}

	for _, srv := range svc.nonDoH {
		go mustStartServer(srv)

		log.Info("websvc: non-doh %s: server is started", srv.Addr)
	}

	return nil
}

// mustStartServer is a helper function that starts srv and panics if there are
// any errors.  It panics if one of the servers could not start, bringing down
// the whole service.
func mustStartServer(srv *http.Server) {
	if srv.TLSConfig == nil {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}

		return
	}

	l, err := tls.Listen("tcp", srv.Addr, srv.TLSConfig)
	if err != nil {
		panic(err)
	}

	err = srv.Serve(l)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

// Shutdown implements the agd.Service interface for *Service.  svc may be nil.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	if svc == nil {
		return nil
	}

	serverGroups := []struct {
		name string
		srvs []*http.Server
	}{{
		name: "linked ip",
		srvs: svc.linkedIP,
	}, {
		name: "safe browsing",
		srvs: svc.safeBrowsing,
	}, {
		name: "adult blocking",
		srvs: svc.adultBlocking,
	}, {
		name: "non-doh",
		srvs: svc.adultBlocking,
	}}

	for _, g := range serverGroups {
		err = shutdownServers(ctx, g.srvs, g.name)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}
	}

	return nil
}

// shutdownServers is a helper function that shuts down srvs and logs successful
// shutdowns.
func shutdownServers(ctx context.Context, srvs []*http.Server, name string) (err error) {
	for _, srv := range srvs {
		err = srv.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("%s server %s shutdown: %w", name, srv.Addr, err)
		}

		log.Info("websvc: %s %s: server is shutdown", name, srv.Addr)
	}

	return nil
}
