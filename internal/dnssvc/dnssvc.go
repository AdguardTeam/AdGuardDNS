// Package dnssvc contains AdGuard DNS's main DNS services.
//
// Prefer to keep all mentions of module dnsserver within this package and
// package agd.
package dnssvc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	dnssrvprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/miekg/dns"
)

// Service is the main DNS service of AdGuard DNS.
type Service struct {
	groups []*serverGroup
}

// serverGroup is a group of servers.
type serverGroup struct {
	name    agd.ServerGroupName
	servers []*server
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

// listener is a Listener along with some of its associated data.
type listener struct {
	Listener

	name string
}

// New returns a new DNS service.
func New(c *Config) (svc *Service, err error) {
	// Use either the configured listener initializer or the default one.
	newListener := c.NewListener
	if newListener == nil {
		newListener = NewListener
	}

	mtrcListener, err := dnssrvprom.NewServerMetricsListener(
		c.MetricsNamespace,
		c.PrometheusRegisterer,
	)
	if err != nil {
		return nil, fmt.Errorf("metrics listener: %w", err)
	}

	errCollListener := &errCollMetricsListener{
		errColl:      c.ErrColl,
		baseListener: mtrcListener,
	}

	// Configure the service itself.
	groups := make([]*serverGroup, 0, len(c.ServerGroups))

	for _, srvGrp := range c.ServerGroups {
		g := &serverGroup{
			name: srvGrp.Name,
		}

		g.servers, err = newServers(c, srvGrp, errCollListener, newListener)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", srvGrp.Name, err)
		}

		groups = append(groups, g)
	}

	svc = &Service{
		groups: groups,
	}

	return svc, nil
}

// newServers creates a slice of servers.
func newServers(
	c *Config,
	srvGrp *ServerGroupConfig,
	errCollListener *errCollMetricsListener,
	newListener NewListenerFunc,
) (servers []*server, err error) {
	servers = make([]*server, 0, len(srvGrp.Servers))

	for _, srv := range srvGrp.Servers {
		k := HandlerKey{
			Server:      srv,
			ServerGroup: srvGrp,
		}
		handler, ok := c.Handlers[k]
		if !ok {
			return nil, fmt.Errorf("no handler for server %q of group %q", srv.Name, srvGrp.Name)
		}

		s := &server{
			name:    srv.Name,
			handler: handler,
		}

		s.listeners, err = newListeners(c, srv, handler, errCollListener, newListener)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", s.name, err)
		}

		servers = append(servers, s)
	}

	return servers, nil
}

// newListeners creates a slice of listeners for a server.
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
		baseConf := &dnsserver.ConfigBase{
			// TODO(a.garipov):  Consider making servers add the address instead
			// of module users doing that.  Including the correct handling of
			// addresses with zero port.
			BaseLogger: c.BaseLogger.With(
				"listener_addr", addr,
				"listener_name", name,
				slogutil.KeyPrefix, "dnsserver",
			),
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
			Addr: addr,
		}

		l := &listener{
			name: name,
		}

		l.Listener, err = newListener(srv, baseConf, c.NonDNS)
		if err != nil {
			return nil, fmt.Errorf("bind data at index %d: %w", i, err)
		}

		listeners = append(listeners, l)
	}

	return listeners, nil
}

// listenerName returns a standard name for a listener.
func listenerName(srvName agd.ServerName, addr string, proto agd.Protocol) (name string) {
	return fmt.Sprintf("%s/%s/%s", srvName, proto, addr)
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

// type check
var _ service.Interface = (*Service)(nil)

// Start implements the [service.Interface] interface for *Service.  It panics
// if one of the listeners could not start.
func (svc *Service) Start(ctx context.Context) (err error) {
	for _, g := range svc.groups {
		for _, s := range g.servers {
			for _, l := range s.listeners {
				// Consider inability to start any one DNS listener a fatal
				// error.
				mustStartListener(ctx, g.name, s.name, l)
			}
		}
	}

	return nil
}

// mustStartListener starts l and panics on any error.
func mustStartListener(
	ctx context.Context,
	srvGrp agd.ServerGroupName,
	srv agd.ServerName,
	l *listener,
) {
	err := l.Start(ctx)
	if err != nil {
		panic(fmt.Errorf("group %q: server %q: starting %q: %w", srvGrp, srv, l.name, err))
	}
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

// Handle is a simple helper to test the handling of DNS requests.
//
// TODO(a.garipov):  Remove once the refactoring is complete.
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

// NewListener returns a new Listener.  It is the default DNS listener
// constructor.
//
// TODO(a.garipov):  Replace this in tests with [netext.ListenConfig].
func NewListener(
	s *agd.Server,
	baseConf *dnsserver.ConfigBase,
	nonDNS http.Handler,
) (l Listener, err error) {
	defer func() { err = errors.Annotate(err, "listener %q: %w", baseConf.Name) }()

	tcpConf := s.TCPConf
	quicConf := s.QUICConf
	switch p := s.Protocol; p {
	case agd.ProtoDNS:
		udpConf := s.UDPConf
		l = dnsserver.NewServerDNS(&dnsserver.ConfigDNS{
			Base:               baseConf,
			ReadTimeout:        s.ReadTimeout,
			WriteTimeout:       s.WriteTimeout,
			MaxUDPRespSize:     udpConf.MaxRespSize,
			TCPIdleTimeout:     tcpConf.IdleTimeout,
			MaxPipelineCount:   tcpConf.MaxPipelineCount,
			MaxPipelineEnabled: tcpConf.MaxPipelineEnabled,
		})
	case agd.ProtoDNSCrypt:
		dcConf := s.DNSCrypt
		l = dnsserver.NewServerDNSCrypt(&dnsserver.ConfigDNSCrypt{
			Base:         baseConf,
			ProviderName: dcConf.ProviderName,
			ResolverCert: dcConf.Cert,
		})
	case agd.ProtoDoH:
		l = dnsserver.NewServerHTTPS(&dnsserver.ConfigHTTPS{
			Base:              baseConf,
			TLSConfDefault:    s.TLS.Default,
			TLSConfH3:         s.TLS.H3,
			NonDNSHandler:     nonDNS,
			MaxStreamsPerPeer: quicConf.MaxStreamsPerPeer,
			QUICLimitsEnabled: quicConf.QUICLimitsEnabled,
		})
	case agd.ProtoDoQ:
		l = dnsserver.NewServerQUIC(&dnsserver.ConfigQUIC{
			TLSConfig:         s.TLS.Default,
			Base:              baseConf,
			MaxStreamsPerPeer: quicConf.MaxStreamsPerPeer,
			QUICLimitsEnabled: quicConf.QUICLimitsEnabled,
		})
	case agd.ProtoDoT:
		l = dnsserver.NewServerTLS(&dnsserver.ConfigTLS{
			DNS: &dnsserver.ConfigDNS{
				Base:               baseConf,
				ReadTimeout:        s.ReadTimeout,
				WriteTimeout:       s.WriteTimeout,
				MaxPipelineEnabled: tcpConf.MaxPipelineEnabled,
				MaxPipelineCount:   tcpConf.MaxPipelineCount,
				TCPIdleTimeout:     tcpConf.IdleTimeout,
			},
			TLSConfig: s.TLS.Default,
		})
	default:
		return nil, fmt.Errorf("protocol: %w: %d", errors.ErrBadEnumValue, p)
	}

	return l, nil
}
