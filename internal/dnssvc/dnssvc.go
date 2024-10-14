// Package dnssvc contains AdGuard DNS's main DNS services.
//
// Prefer to keep all mentions of module dnsserver within this package and
// package agd.
package dnssvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/cmd/plugin"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	dnssrvprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/mainmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preupstream"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/ratelimitmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Config is the configuration of the AdGuard DNS service.
type Config struct {
	// BaseLogger is used to create loggers with custom prefixes for middlewares
	// and the service itself.
	BaseLogger *slog.Logger

	// Messages is the message constructor used to create blocked and other
	// messages for this DNS service.
	Messages *dnsmsg.Constructor

	// Cloner is used to clone messages more efficiently by disposing of parts
	// of DNS responses for later reuse.
	Cloner *dnsmsg.Cloner

	// ControlConf is the configuration of socket options.
	ControlConf *netext.ControlConfig

	// ConnLimiter, if not nil, is used to limit the number of simultaneously
	// active stream-connections.
	ConnLimiter *connlimiter.Limiter

	// HumanIDParser is used to normalize and parse human-readable device
	// identifiers.
	HumanIDParser *agd.HumanIDParser

	// PluginRegistry is used to override configuration parameters.
	PluginRegistry *plugin.Registry

	// AccessManager is used to block requests.
	AccessManager access.Interface

	// SafeBrowsing is the safe browsing TXT hash matcher.
	SafeBrowsing filter.HashMatcher

	// BillStat is used to collect billing statistics.
	BillStat billstat.Recorder

	// CacheManager is the global cache manager.  CacheManager must not be nil.
	CacheManager agdcache.Manager

	// ProfileDB is the AdGuard DNS profile database used to fetch data about
	// profiles, devices, and so on.
	ProfileDB profiledb.Interface

	// PrometheusRegisterer is used to register Prometheus metrics.
	PrometheusRegisterer prometheus.Registerer

	// DNSCheck is used by clients to check if they use AdGuard DNS.
	DNSCheck dnscheck.Interface

	// NonDNS is the handler for non-DNS HTTP requests.
	NonDNS http.Handler

	// DNSDB is used to update anonymous statistics about DNS queries.
	DNSDB dnsdb.Interface

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl errcoll.Interface

	// FilterStorage is the storage of all filters.
	FilterStorage filter.Storage

	// GeoIP is the GeoIP database used to detect geographic data about IP
	// addresses in requests and responses.
	GeoIP geoip.Interface

	// QueryLog is used to write the logs into.
	QueryLog querylog.Interface

	// RuleStat is used to collect statistics about matched filtering rules and
	// rule lists.
	RuleStat rulestat.Interface

	// NewListener, when set, is used instead of the package-level function
	// NewListener when creating a DNS listener.
	//
	// TODO(a.garipov): The handler and service logic should really not be
	// intertwined in this way.  See AGDNS-1327.
	NewListener NewListenerFunc

	// Handler is used as the main DNS handler instead of a simple forwarder.
	// It must not be nil.
	//
	// TODO(a.garipov): Think of a better way to make the DNS server logic more
	// testable.
	Handler dnsserver.Handler

	// RateLimit is used for allow or decline requests.
	RateLimit ratelimit.Interface

	// MetricsNamespace is a namespace for Prometheus metrics.  It must be a
	// valid Prometheus metric label.
	MetricsNamespace string

	// FilteringGroups are the DNS filtering groups.  Each element must be
	// non-nil.
	FilteringGroups map[agd.FilteringGroupID]*agd.FilteringGroup

	// ServerGroups are the DNS server groups.  Each element must be non-nil.
	ServerGroups []*agd.ServerGroup

	// HandleTimeout defines the timeout for the entire handling of a single
	// query.
	HandleTimeout time.Duration

	// CacheSize is the size of the DNS cache for domain names that don't
	// support ECS.
	//
	// TODO(a.garipov): Extract this and following fields to cache configuration
	// struct.
	CacheSize int

	// ECSCacheSize is the size of the DNS cache for domain names that support
	// ECS.
	ECSCacheSize int

	// CacheMinTTL is the minimum supported TTL for cache items.  This setting
	// is used when UseCacheTTLOverride set to true.
	CacheMinTTL time.Duration

	// UseCacheTTLOverride shows if the TTL overrides logic should be used.
	UseCacheTTLOverride bool

	// UseECSCache shows if the EDNS Client Subnet (ECS) aware cache should be
	// used.
	UseECSCache bool
}

type (
	// MainMiddlewareMetrics is a re-export of the internal filtering-middleware
	// metrics interface.
	MainMiddlewareMetrics = mainmw.Metrics

	// RatelimitMiddlewareMetrics is a re-export of the metrics interface of the
	// internal access and ratelimiting middleware.
	RatelimitMiddlewareMetrics = ratelimitmw.Metrics
)

// New returns a new DNS service.
func New(c *Config) (svc *Service, err error) {
	// Use either the configured listener initializer or the default one.
	newListener := c.NewListener
	if newListener == nil {
		newListener = NewListener
	}

	// Configure the end of the request handling pipeline.
	handler := c.Handler
	if handler == nil {
		return nil, errors.Error("handler in config must not be nil")
	}

	// Configure the pre-upstream middleware common for all servers of all
	// groups.
	preUps := preupstream.New(&preupstream.Config{
		Cloner:              c.Cloner,
		CacheManager:        c.CacheManager,
		DB:                  c.DNSDB,
		GeoIP:               c.GeoIP,
		CacheSize:           c.CacheSize,
		ECSCacheSize:        c.ECSCacheSize,
		UseECSCache:         c.UseECSCache,
		CacheMinTTL:         c.CacheMinTTL,
		UseCacheTTLOverride: c.UseCacheTTLOverride,
	})
	handler = preUps.Wrap(handler)

	errCollListener := &errCollMetricsListener{
		errColl:      c.ErrColl,
		baseListener: dnssrvprom.NewServerMetricsListener(c.MetricsNamespace),
	}

	// Configure the service itself.
	groups := make([]*serverGroup, len(c.ServerGroups))
	svc = &Service{
		groups: groups,
	}

	mainMwMtrc, err := newMainMiddlewareMetrics(c)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	rlMwMtrc, err := metrics.NewDefaultRatelimitMiddleware(c.MetricsNamespace, c.PrometheusRegisterer)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	for i, srvGrp := range c.ServerGroups {
		// The Filtering Middlewares
		//
		// These are middlewares common to all filtering and server groups.
		// They change the flow of request handling, so they are separated.

		dnsHdlr := dnsserver.WithMiddlewares(
			handler,
			preservice.New(&preservice.Config{
				Messages:    c.Messages,
				HashMatcher: c.SafeBrowsing,
				Checker:     c.DNSCheck,
			}),
			mainmw.New(&mainmw.Config{
				Metrics:       mainMwMtrc,
				Messages:      c.Messages,
				Cloner:        c.Cloner,
				BillStat:      c.BillStat,
				ErrColl:       c.ErrColl,
				FilterStorage: c.FilterStorage,
				GeoIP:         c.GeoIP,
				QueryLog:      c.QueryLog,
				RuleStat:      c.RuleStat,
			}),
		)

		var servers []*server
		servers, err = newServers(c, srvGrp, dnsHdlr, rlMwMtrc, errCollListener, newListener)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", srvGrp.Name, err)
		}

		groups[i] = &serverGroup{
			name:    srvGrp.Name,
			servers: servers,
		}
	}

	return svc, nil
}

// newMainMiddlewareMetrics returns a filtering-middleware metrics
// implementation from the config.
func newMainMiddlewareMetrics(c *Config) (mainMwMtrc MainMiddlewareMetrics, err error) {
	mainMwMtrc = c.PluginRegistry.MainMiddlewareMetrics()
	if mainMwMtrc != nil {
		return mainMwMtrc, nil
	}

	mainMwMtrc, err = metrics.NewDefaultMainMiddleware(c.MetricsNamespace, c.PrometheusRegisterer)
	if err != nil {
		return nil, fmt.Errorf("mainmw metrics: %w", err)
	}

	return mainMwMtrc, nil
}

// server is a group of listeners.
//
// Note that the definition of a “server” differs between AdGuard DNS and the
// dnsserver module.  In the latter, a server is a listener bound to a single
// address, while in AGDNS, it's a collection of these listeners.
type server struct {
	name      agd.ServerName
	handler   dnsserver.Handler
	listeners []*listener
}

// serverGroup is a group of servers.
type serverGroup struct {
	name    agd.ServerGroupName
	servers []*server
}

// Service is the main DNS service of AdGuard DNS.
type Service struct {
	groups []*serverGroup
}

// mustStartListener starts l and panics on any error.
func mustStartListener(
	grp agd.ServerGroupName,
	srv agd.ServerName,
	l *listener,
) {
	err := l.Start(context.Background())
	if err != nil {
		panic(fmt.Errorf("group %q: server %q: starting %q: %w", grp, srv, l.name, err))
	}
}

// type check
var _ service.Interface = (*Service)(nil)

// Start implements the [service.Interface] interface for *Service.  It panics
// if one of the listeners could not start.
func (svc *Service) Start(_ context.Context) (err error) {
	for _, g := range svc.groups {
		for _, s := range g.servers {
			for _, l := range s.listeners {
				// Consider inability to start any one DNS listener a fatal
				// error.
				mustStartListener(g.name, s.name, l)
			}
		}
	}

	return nil
}

// shutdownListeners is a helper function that shuts down all listeners of a
// server.
func shutdownListeners(ctx context.Context, listeners []*listener) (err error) {
	for _, l := range listeners {
		err = l.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("shutting down listener %q: %w", l.name, err)
		}
	}

	return nil
}

// Shutdown implements the [service.Interface] interface for *Service.
func (svc *Service) Shutdown(ctx context.Context) (err error) {
	var errs []error
	for _, g := range svc.groups {
		for _, s := range g.servers {
			err = shutdownListeners(ctx, s.listeners)
			if err != nil {
				errs = append(errs, fmt.Errorf("group %q: server %q: %w", g.name, s.name, err))
			}
		}
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("shutting down dns service: %w", err)
	}

	return nil
}

// Handle is a simple helper to test the handling of DNS requests.
//
// TODO(a.garipov): Remove once the mainmw refactoring is complete.
func (svc *Service) Handle(
	ctx context.Context,
	grpName agd.ServerGroupName,
	srvName agd.ServerName,
	rw dnsserver.ResponseWriter,
	r *dns.Msg,
) (err error) {
	var grp *serverGroup
	for _, g := range svc.groups {
		if g.name == grpName {
			grp = g

			break
		}
	}

	if grp == nil {
		return errors.Error("no such server group")
	}

	var srv *server
	for _, s := range grp.servers {
		if s.name == srvName {
			srv = s

			break
		}
	}

	if srv == nil {
		return errors.Error("no such server")
	}

	return srv.handler.ServeDNS(ctx, rw, r)
}

// Listener is a type alias for dnsserver.Server to make internal naming more
// consistent.
type Listener = dnsserver.Server

// NewListenerFunc is the type for DNS listener constructors.
type NewListenerFunc func(
	s *agd.Server,
	baseConf dnsserver.ConfigBase,
	nonDNS http.Handler,
) (l Listener, err error)

// listener is a Listener along with some of its associated data.
type listener struct {
	Listener

	name string
}

// listenerName returns a standard name for a listener.
func listenerName(srvName agd.ServerName, addr string, proto agd.Protocol) (name string) {
	return fmt.Sprintf("%s/%s/%s", srvName, proto, addr)
}

// NewListener returns a new Listener.  It is the default DNS listener
// constructor.
//
// TODO(a.garipov): Replace this in tests with [netext.ListenConfig].
func NewListener(
	s *agd.Server,
	baseConf dnsserver.ConfigBase,
	nonDNS http.Handler,
) (l Listener, err error) {
	defer func() { err = errors.Annotate(err, "listener %q: %w", baseConf.Name) }()

	tcpConf := s.TCPConf
	quicConf := s.QUICConf
	switch p := s.Protocol; p {
	case agd.ProtoDNS:
		udpConf := s.UDPConf
		l = dnsserver.NewServerDNS(dnsserver.ConfigDNS{
			ConfigBase:         baseConf,
			ReadTimeout:        s.ReadTimeout,
			WriteTimeout:       s.WriteTimeout,
			MaxUDPRespSize:     udpConf.MaxRespSize,
			TCPIdleTimeout:     tcpConf.IdleTimeout,
			MaxPipelineCount:   tcpConf.MaxPipelineCount,
			MaxPipelineEnabled: tcpConf.MaxPipelineEnabled,
		})
	case agd.ProtoDNSCrypt:
		dcConf := s.DNSCrypt
		l = dnsserver.NewServerDNSCrypt(dnsserver.ConfigDNSCrypt{
			ConfigBase:           baseConf,
			DNSCryptProviderName: dcConf.ProviderName,
			DNSCryptResolverCert: dcConf.Cert,
		})
	case agd.ProtoDoH:
		l = dnsserver.NewServerHTTPS(dnsserver.ConfigHTTPS{
			ConfigBase:        baseConf,
			TLSConfig:         s.TLS,
			NonDNSHandler:     nonDNS,
			MaxStreamsPerPeer: quicConf.MaxStreamsPerPeer,
			QUICLimitsEnabled: quicConf.QUICLimitsEnabled,
		})
	case agd.ProtoDoQ:
		l = dnsserver.NewServerQUIC(dnsserver.ConfigQUIC{
			TLSConfig:         s.TLS,
			ConfigBase:        baseConf,
			MaxStreamsPerPeer: quicConf.MaxStreamsPerPeer,
			QUICLimitsEnabled: quicConf.QUICLimitsEnabled,
		})
	case agd.ProtoDoT:
		l = dnsserver.NewServerTLS(dnsserver.ConfigTLS{
			ConfigDNS: dnsserver.ConfigDNS{
				ConfigBase:         baseConf,
				ReadTimeout:        s.ReadTimeout,
				WriteTimeout:       s.WriteTimeout,
				MaxPipelineEnabled: tcpConf.MaxPipelineEnabled,
				MaxPipelineCount:   tcpConf.MaxPipelineCount,
				TCPIdleTimeout:     tcpConf.IdleTimeout,
			},
			TLSConfig: s.TLS,
		})
	default:
		return nil, fmt.Errorf("bad protocol %v", p)
	}

	return l, nil
}

// contextConstructor is a [dnsserver.ContextConstructor] implementation that
// that returns a context with the given timeout as well as a new
// [agd.RequestID].
type contextConstructor struct {
	timeout time.Duration
}

// newContextConstructor returns a new properly initialized *contextConstructor.
func newContextConstructor(timeout time.Duration) (c *contextConstructor) {
	return &contextConstructor{
		timeout: timeout,
	}
}

// type check
var _ dnsserver.ContextConstructor = (*contextConstructor)(nil)

// New implements the [dnsserver.ContextConstructor] interface for
// *contextConstructor.  It returns a context with a new [agd.RequestID] as well
// as its timeout and the corresponding cancelation function.
func (c *contextConstructor) New() (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
	ctx = agd.WithRequestID(ctx, agd.NewRequestID())

	return ctx, cancel
}

// newServers creates a slice of servers.
//
// TODO(a.garipov):  Refactor this into a builder pattern.
func newServers(
	c *Config,
	srvGrp *agd.ServerGroup,
	handler dnsserver.Handler,
	rlMwMtrc ratelimitmw.Metrics,
	errCollListener *errCollMetricsListener,
	newListener NewListenerFunc,
) (servers []*server, err error) {
	servers = make([]*server, len(srvGrp.Servers))

	for i, s := range srvGrp.Servers {
		// The Initial Middlewares
		//
		// These middlewares are either specific to the server or must be the
		// furthest away from the handler and thus are the first to process
		// a request.

		// Assume that all the validations have been made during the
		// configuration validation step back in package cmd.  If we ever get
		// new ways of receiving configuration, remove this assumption and
		// validate fg.
		fg := c.FilteringGroups[srvGrp.FilteringGroup]

		df := newDeviceFinder(c, srvGrp, s)
		rlm := ratelimitmw.New(&ratelimitmw.Config{
			Logger:         c.BaseLogger.With(slogutil.KeyPrefix, "ratelimitmw"),
			Messages:       c.Messages,
			FilteringGroup: fg,
			ServerGroup:    srvGrp,
			Server:         s,
			AccessManager:  c.AccessManager,
			DeviceFinder:   df,
			ErrColl:        c.ErrColl,
			GeoIP:          c.GeoIP,
			Metrics:        rlMwMtrc,
			Limiter:        c.RateLimit,
			// Only apply rate-limiting logic to plain DNS.
			Protocols: []agd.Protocol{agd.ProtoDNS},
		})
		if err != nil {
			return nil, fmt.Errorf("ratelimit: %w", err)
		}

		imw := initial.New(&initial.Config{
			Logger: c.BaseLogger.With(slogutil.KeyPrefix, "initmw"),
		})

		h := dnsserver.WithMiddlewares(
			handler,

			// Keep the rate limiting and access middlewares as the outer ones
			// to make sure that the application logic isn't touched if the
			// request is ratelimited or blocked by access settings.
			rlm,
			imw,
		)

		srvName := s.Name

		var listeners []*listener
		listeners, err = newListeners(c, s, h, errCollListener, newListener)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", srvName, err)
		}

		servers[i] = &server{
			name:      srvName,
			handler:   h,
			listeners: listeners,
		}
	}

	return servers, nil
}

// newDeviceFinder returns a new [agd.DeviceFinder] for a server based on the
// configuration.
func newDeviceFinder(c *Config, g *agd.ServerGroup, s *agd.Server) (df agd.DeviceFinder) {
	if !g.ProfilesEnabled {
		return agd.EmptyDeviceFinder{}
	}

	return devicefinder.NewDefault(&devicefinder.Config{
		Logger:        c.BaseLogger.With(slogutil.KeyPrefix, "devicefinder"),
		ProfileDB:     c.ProfileDB,
		HumanIDParser: c.HumanIDParser,
		Server:        s,
		DeviceDomains: g.TLS.DeviceDomains,
	})
}

// newServers creates a slice of listeners for a server.
func newListeners(
	c *Config,
	srv *agd.Server,
	handler dnsserver.Handler,
	errCollListener *errCollMetricsListener,
	newListener NewListenerFunc,
) (listeners []*listener, err error) {
	bindData := srv.BindData()
	listeners = make([]*listener, 0, len(bindData))
	for i, bindData := range bindData {
		var addr string
		if bindData.PrefixAddr == nil {
			addr = bindData.AddrPort.String()
		} else {
			addr = bindData.PrefixAddr.String()
		}

		proto := srv.Protocol

		name := listenerName(srv.Name, addr, proto)
		baseConf := dnsserver.ConfigBase{
			Network:        dnsserver.NetworkAny,
			Handler:        handler,
			Metrics:        errCollListener,
			Disposer:       c.Cloner,
			RequestContext: newContextConstructor(c.HandleTimeout),
			ListenConfig: newListenConfig(
				bindData.ListenConfig,
				c.ControlConf,
				c.ConnLimiter,
				proto,
			),
			Name: name,
			Addr: addr,
		}

		var l Listener
		l, err = newListener(srv, baseConf, c.NonDNS)
		if err != nil {
			return nil, fmt.Errorf("bind data at index %d: %w", i, err)
		}

		listeners = append(listeners, &listener{
			name:     name,
			Listener: l,
		})
	}

	return listeners, nil
}

// newListenConfig returns the netext.ListenConfig used by the plain-DNS
// servers.  The resulting ListenConfig sets additional socket flags and
// processes the control messages of connections created with ListenPacket.
// Additionally, if l is not nil, it is used to limit the number of
// simultaneously active stream-connections.
func newListenConfig(
	original netext.ListenConfig,
	ctrlConf *netext.ControlConfig,
	l *connlimiter.Limiter,
	p agd.Protocol,
) (lc netext.ListenConfig) {
	if original != nil {
		if l == nil {
			return original
		}

		return connlimiter.NewListenConfig(original, l)
	}

	if p == agd.ProtoDNS {
		lc = netext.DefaultListenConfigWithOOB(ctrlConf)
	} else {
		lc = netext.DefaultListenConfig(ctrlConf)
	}

	if l != nil {
		lc = connlimiter.NewListenConfig(lc, l)
	}

	return lc
}
