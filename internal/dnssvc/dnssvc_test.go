package dnssvc_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// type check
var _ agd.Refresher = (*forward.Handler)(nil)

// Test Mocks

// type check
var _ dnssvc.Listener = (*testListener)(nil)

// testListener is a [dnssvc.Listener] for tests.
type testListener struct {
	onStart        func(ctx context.Context) (err error)
	onShutdown     func(ctx context.Context) (err error)
	onName         func() (name string)
	onProto        func() (proto dnsserver.Protocol)
	onNetwork      func() (network dnsserver.Network)
	onAddr         func() (addr string)
	onLocalTCPAddr func() (addr net.Addr)
	onLocalUDPAddr func() (addr net.Addr)
}

// Name implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Name() (name string) {
	return l.onName()
}

// Proto implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Proto() (proto dnsserver.Protocol) {
	return l.onProto()
}

// Network implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Network() (network dnsserver.Network) {
	return l.onNetwork()
}

// Addr implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Addr() (addr string) {
	return l.onAddr()
}

// Start implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Start(ctx context.Context) (err error) {
	return l.onStart(ctx)
}

// Shutdown implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) Shutdown(ctx context.Context) (err error) {
	return l.onShutdown(ctx)
}

// LocalTCPAddr implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) LocalTCPAddr() (addr net.Addr) {
	return l.onLocalTCPAddr()
}

// LocalUDPAddr implements the [dnsserver.Server] interface for *testListener.
func (l *testListener) LocalUDPAddr() (addr net.Addr) {
	return l.onLocalUDPAddr()
}

// newTestListener returns a *testListener all of methods of which panic with
// a "not implemented" message.
func newTestListener() (tl *testListener) {
	return &testListener{
		onName:         func() (_ string) { panic("not implemented") },
		onProto:        func() (_ dnsserver.Protocol) { panic("not implemented") },
		onNetwork:      func() (_ dnsserver.Network) { panic("not implemented") },
		onAddr:         func() (_ string) { panic("not implemented") },
		onStart:        func(_ context.Context) (err error) { panic("not implemented") },
		onShutdown:     func(_ context.Context) (err error) { panic("not implemented") },
		onLocalUDPAddr: func() (_ net.Addr) { panic("not implemented") },
		onLocalTCPAddr: func() (_ net.Addr) { panic("not implemented") },
	}
}

// newTestListenerFunc returns a new NewListenerFunc that returns the provided
// listener.
func newTestListenerFunc(tl *testListener) (f dnssvc.NewListenerFunc) {
	return func(
		_ *agd.Server,
		_ string,
		_ string,
		_ dnsserver.Handler,
		_ http.Handler,
		_ agd.ErrorCollector,
		_ netext.ListenConfig,
	) (l dnssvc.Listener, err error) {
		return tl, nil
	}
}

// type check
var _ dnsserver.ResponseWriter = (*testResponseWriter)(nil)

// testResponseWriter is a simple dnsserver.ResponseWriter for tests.
type testResponseWriter struct {
	onLocalAddr  func() (a net.Addr)
	onRemoteAddr func() (a net.Addr)
	onWriteMsg   func(ctx context.Context, req, resp *dns.Msg) (err error)
}

// LocalAddr returns the net.Addr of the server.
func (rw *testResponseWriter) LocalAddr() (a net.Addr) {
	return rw.onLocalAddr()
}

// RemoteAddr returns the net.Addr of the client that sent the current request.
func (rw *testResponseWriter) RemoteAddr() (a net.Addr) {
	return rw.onRemoteAddr()
}

// WriteMsg writes a reply back to the client.
func (rw *testResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	return rw.onWriteMsg(ctx, req, resp)
}

// Tests

func TestService_Start(t *testing.T) {
	var numStart, numShutdown atomic.Uint64

	tl := newTestListener()
	tl.onStart = func(_ context.Context) (err error) {
		numStart.Add(1)

		return nil
	}
	tl.onShutdown = func(_ context.Context) (err error) {
		numShutdown.Add(1)

		return nil
	}

	srv := &agd.Server{
		Name: "test_server",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:53"),
		}},
		Protocol: agd.ProtoDNS,
	}

	c := &dnssvc.Config{
		NewListener: newTestListenerFunc(tl),
		Handler:     dnsservertest.DefaultHandler(),
		ServerGroups: []*agd.ServerGroup{{
			Name:    "test_group",
			Servers: []*agd.Server{srv},
		}},
	}

	svc, err := dnssvc.New(c)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		err = svc.Start()
		assert.NoError(t, err)
		assert.Equal(t, uint64(1), numStart.Load())
	})

	require.NotPanics(t, func() {
		err = svc.Shutdown(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, uint64(1), numShutdown.Load())
	})
}

func TestNew(t *testing.T) {
	srvs := []*agd.Server{{
		DNSCrypt: nil,
		TLS:      nil,
		Name:     "test_server_dns",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:53"),
		}},
		Protocol: agd.ProtoDNS,
	}, {
		DNSCrypt: &agd.DNSCryptConfig{},
		TLS:      nil,
		Name:     "test_server_dnscrypt_tcp",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:8853"),
		}},
		Protocol: agd.ProtoDNSCrypt,
	}, {
		DNSCrypt: nil,
		TLS:      &tls.Config{},
		Name:     "test_server_doh",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:443"),
		}},
		Protocol: agd.ProtoDoH,
	}, {
		DNSCrypt: nil,
		TLS:      &tls.Config{},
		Name:     "test_server_doq",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:853"),
		}},
		Protocol: agd.ProtoDoQ,
	}, {
		DNSCrypt: nil,
		TLS:      &tls.Config{},
		Name:     "test_server_dot",
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:853"),
		}},
		Protocol: agd.ProtoDoT,
	}}

	c := &dnssvc.Config{
		Handler: dnsservertest.DefaultHandler(),
		ServerGroups: []*agd.ServerGroup{{
			Name:    "test_group",
			Servers: srvs,
		}},
	}

	svc, err := dnssvc.New(c)
	require.NoError(t, err)
	require.NotNil(t, svc)
}
