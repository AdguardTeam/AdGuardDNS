// Package dnssvc contains AdGuard DNS's main DNS services.
//
// Prefer to keep all mentions of module dnsserver within this package and
// package agd.
package dnssvc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/accessmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// DNS Service Definition
//
// Note that the definition of a “server” differs between AdGuard DNS and the
// dnsserver module.  In the latter, a server is a listener bound to a single
// address, while in AGDNS, it's a collection of these listeners.

// Config is the configuration of the AdGuard DNS service.
type Config struct {
	// Messages is the message constructor used to create blocked and other
	// messages for this DNS service.
	Messages *dnsmsg.Constructor

	// ControlConf is the configuration of socket options.
	ControlConf *netext.ControlConfig

	// ConnLimiter, if not nil, is used to limit the number of simultaneously
	// active stream-connections.
	ConnLimiter *connlimiter.Limiter

	// AccessManager is used to block requests.
	AccessManager access.Interface

	// SafeBrowsing is the safe browsing TXT hash matcher.
	SafeBrowsing filter.HashMatcher

	// BillStat is used to collect billing statistics.
	BillStat billstat.Recorder

	// ProfileDB is the AdGuard DNS profile database used to fetch data about
	// profiles, devices, and so on.
	ProfileDB profiledb.Interface

	// DNSCheck is used by clients to check if they use AdGuard DNS.
	DNSCheck dnscheck.Interface

	// NonDNS is the handler for non-DNS HTTP requests.
	NonDNS http.Handler

	// DNSDB is used to update anonymous statistics about DNS queries.
	DNSDB dnsdb.Interface

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl agd.ErrorCollector

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

	// FilteringGroups are the DNS filtering groups.  Each element must be
	// non-nil.
	FilteringGroups map[agd.FilteringGroupID]*agd.FilteringGroup

	// ServerGroups are the DNS server groups.  Each element must be non-nil.
	ServerGroups []*agd.ServerGroup

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

	// ResearchMetrics controls whether research metrics are enabled or not.
	// This is a set of metrics that we may need temporary, so its collection is
	// controlled by a separate setting.
	ResearchMetrics bool

	// ResearchLogs controls whether logging of additional info for research
	// purposes is enabled.  These logs may be overly verbose and are only
	// required temporary, that's why it's controlled by a separate setting.
	// This setting will only be used when ResearchMetrics is also set to true.
	ResearchLogs bool
}

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
	preUps := &preUpstreamMw{
		db:                  c.DNSDB,
		geoIP:               c.GeoIP,
		cacheSize:           c.CacheSize,
		ecsCacheSize:        c.ECSCacheSize,
		useECSCache:         c.UseECSCache,
		cacheMinTTL:         c.CacheMinTTL,
		useCacheTTLOverride: c.UseCacheTTLOverride,
	}
	handler = preUps.Wrap(handler)

	// Configure the service itself.
	groups := make([]*serverGroup, len(c.ServerGroups))
	svc = &Service{
		messages:        c.Messages,
		billStat:        c.BillStat,
		errColl:         c.ErrColl,
		fltStrg:         c.FilterStorage,
		geoIP:           c.GeoIP,
		queryLog:        c.QueryLog,
		ruleStat:        c.RuleStat,
		groups:          groups,
		researchMetrics: c.ResearchMetrics,
		researchLog:     c.ResearchLogs,
	}

	for i, srvGrp := range c.ServerGroups {
		// The Filtering Middlewares
		//
		// These are middlewares common to all filtering and server groups.
		// They change the flow of request handling, so they are separated.
		//
		// TODO(a.garipov):  Merge with some other middlewares.

		dnsHdlr := dnsserver.WithMiddlewares(
			handler,
			&preServiceMw{
				messages:    c.Messages,
				hashMatcher: c.SafeBrowsing,
				checker:     c.DNSCheck,
			},
			svc,
		)

		var servers []*server
		servers, err = newServers(c, srvGrp, dnsHdlr, newListener)
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

// server is a group of listeners.
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

// type check
var _ agd.Service = (*Service)(nil)

// Service is the main DNS service of AdGuard DNS.
type Service struct {
	messages *dnsmsg.Constructor
	billStat billstat.Recorder
	errColl  agd.ErrorCollector
	fltStrg  filter.Storage
	geoIP    geoip.Interface
	queryLog querylog.Interface
	ruleStat rulestat.Interface
	groups   []*serverGroup

	// researchMetrics enables reporting metrics that may be needed for research
	// purposes.
	researchMetrics bool

	// researchLog enables logging of additional information that may be needed
	// for research purposes.  It will only be used when researchMetrics is set
	// to true.
	researchLog bool
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

// Start implements the agd.Service interface for *Service.  It panics if one of
// the listeners could not start.
func (svc *Service) Start() (err error) {
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

// Shutdown implements the agd.Service interface for *Service.
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
	name string,
	addr string,
	h dnsserver.Handler,
	nonDNS http.Handler,
	errColl agd.ErrorCollector,
	lc netext.ListenConfig,
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
func NewListener(
	s *agd.Server,
	name string,
	addr string,
	h dnsserver.Handler,
	nonDNS http.Handler,
	errColl agd.ErrorCollector,
	lc netext.ListenConfig,
) (l Listener, err error) {
	defer func() { err = errors.Annotate(err, "listener %q: %w", name) }()

	dcConf := s.DNSCrypt

	metricsListener := &errCollMetricsListener{
		errColl:      errColl,
		baseListener: prometheus.NewServerMetricsListener(),
	}

	confBase := dnsserver.ConfigBase{
		Name:         name,
		Addr:         addr,
		Network:      dnsserver.NetworkAny,
		Handler:      h,
		Metrics:      metricsListener,
		BaseContext:  ctxWithReqID,
		ListenConfig: lc,
	}

	switch p := s.Protocol; p {
	case agd.ProtoDNS:
		l = dnsserver.NewServerDNS(dnsserver.ConfigDNS{ConfigBase: confBase})
	case agd.ProtoDNSCrypt:
		l = dnsserver.NewServerDNSCrypt(dnsserver.ConfigDNSCrypt{
			ConfigBase:           confBase,
			DNSCryptProviderName: dcConf.ProviderName,
			DNSCryptResolverCert: dcConf.Cert,
		})
	case agd.ProtoDoH:
		l = dnsserver.NewServerHTTPS(dnsserver.ConfigHTTPS{
			ConfigBase:    confBase,
			TLSConfig:     s.TLS,
			NonDNSHandler: nonDNS,
		})
	case agd.ProtoDoQ:
		l = dnsserver.NewServerQUIC(dnsserver.ConfigQUIC{
			ConfigBase: confBase,
			TLSConfig:  s.TLS,
		})
	case agd.ProtoDoT:
		l = dnsserver.NewServerTLS(dnsserver.ConfigTLS{
			ConfigDNS: dnsserver.ConfigDNS{ConfigBase: confBase},
			TLSConfig: s.TLS,
		})
	default:
		return nil, fmt.Errorf("bad protocol %v", p)
	}

	return l, nil
}

// ctxWithReqID returns a context with a new request ID added to it.
func ctxWithReqID() (ctx context.Context) {
	return agd.WithRequestID(context.Background(), agd.NewRequestID())
}

// newServers creates a slice of servers.
func newServers(
	c *Config,
	srvGrp *agd.ServerGroup,
	handler dnsserver.Handler,
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

		// Only apply rate-limiting logic to plain DNS.
		rlProtos := []agd.Protocol{agd.ProtoDNS}

		var rlm *ratelimit.Middleware
		srvName := s.Name
		rlm, err = ratelimit.NewMiddleware(c.RateLimit, rlProtos)
		if err != nil {
			return nil, fmt.Errorf("server %q: ratelimit: %w", srvName, err)
		}

		rlm.Metrics = prometheus.NewRateLimitMetricsListener()

		amw := accessmw.New(&accessmw.Config{
			AccessManager: c.AccessManager,
		})

		imw := initial.New(&initial.Config{
			Messages:       c.Messages,
			FilteringGroup: fg,
			ServerGroup:    srvGrp,
			Server:         s,
			ProfileDB:      c.ProfileDB,
			GeoIP:          c.GeoIP,
			ErrColl:        c.ErrColl,
		})

		h := dnsserver.WithMiddlewares(
			handler,

			// Keep the rate limiting and access middlewares as the outer ones
			// to make sure that the application logic isn't touched if the
			// request is ratelimited or blocked by access settings.
			rlm,
			amw,
			imw,
		)

		var listeners []*listener
		listeners, err = newListeners(c, s, h, newListener)
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

// newServers creates a slice of listeners for a server.
func newListeners(
	c *Config,
	srv *agd.Server,
	handler dnsserver.Handler,
	newListener NewListenerFunc,
) (listeners []*listener, err error) {
	listeners = make([]*listener, 0, len(srv.BindData))
	for i, bindData := range srv.BindData {
		addr := bindData.Address
		if addr == "" {
			addr = bindData.AddrPort.String()
		}

		proto := srv.Protocol
		name := listenerName(srv.Name, addr, proto)

		lc := newListenConfig(bindData.ListenConfig, c.ControlConf, c.ConnLimiter, proto)

		var l Listener
		l, err = newListener(srv, name, addr, handler, c.NonDNS, c.ErrColl, lc)
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
