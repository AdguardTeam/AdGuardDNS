package dnsservertest

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/stretchr/testify/require"
)

// testTimeout is the timeout for test operations.
const testTimeout = 2 * time.Second

// LocalhostAnyPort is the localhost address with unspecified port, which can be
// used for binding to any available port on localhost.
var LocalhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

// newConfigDNSWithDefaults fills in default values for the server
// configuration.  The following default values are used if not specified:
//   - [ConfigBase.BaseLogger] filled with [slogutil.NewDiscardLogger];
//   - [ConfigBase.Handler] filled with [NewDefaultHandler];
//   - [ConfigBase.Name] filled with the test name from [testing.TB];
//   - [ConfigBase.Addr] filled with [LocalhostAnyPort];
//   - others are set as documented in [dnsserver.ConfigDNS].
//
// c must not be nil.
func newConfigDNSWithDefaults(tb testing.TB, c *dnsserver.ConfigDNS) {
	cb := cmp.Or(c.Base, &dnsserver.ConfigBase{})
	base := *cb
	c.Base = &base

	base.BaseLogger = cmp.Or(base.BaseLogger, slogutil.NewDiscardLogger())
	base.Handler = cmp.Or(base.Handler, NewDefaultHandler())
	base.Name = cmp.Or(base.Name, tb.Name())
	base.Addr = cmp.Or(base.Addr, LocalhostAnyPort.String())
}

// RunDNSServer runs a test server with the specified configuration for the
// duration of the test.  It also registers a cleanup function to shut down the
// server.  The following default values are used if not specified:
//   - c is replaced with an empty [dnsserver.ConfigDNS];
//   - [ConfigBase.BaseLogger] filled with [slogutil.NewDiscardLogger];
//   - [ConfigBase.Handler] filled with [NewDefaultHandler];
//   - [ConfigBase.Name] filled with the test name from [testing.TB];
//   - [ConfigBase.Addr] filled with [LocalhostAnyPort];
//   - others are set as documented in [dnsserver.ConfigDNS].
//
// addr is the address that can be used to reach that server.
//
// TODO(a.garipov): s seems to only be used for LocalUDPAddr.  Perhaps, only
// return it?
func RunDNSServer(tb testing.TB, c *dnsserver.ConfigDNS) (s *dnsserver.ServerDNS, addr string) {
	tb.Helper()

	c = cmp.Or(c, &dnsserver.ConfigDNS{})
	conf := *c
	newConfigDNSWithDefaults(tb, &conf)
	c = &conf

	s = dnsserver.NewServerDNS(c)
	require.Equal(tb, dnsserver.ProtoDNS, s.Proto())

	err := runWithRetry(func() (err error) {
		return s.Start(testutil.ContextWithTimeout(tb, testTimeout))
	})
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return s.Shutdown(testutil.ContextWithTimeout(tb, testTimeout))
	})

	localAddr := s.LocalTCPAddr()
	if localAddr == nil {
		localAddr = s.LocalUDPAddr()
	}

	return s, localAddr.String()
}

// RunTLSServer runs a simple test server with the specified handler for the
// duration of the test.  It also registers a cleanup function to shut down the
// server.  The following default values are used if not specified:
//   - c is replaced with an empty [dnsserver.ConfigDNS];
//   - [ConfigBase.BaseLogger] filled with [slogutil.NewDiscardLogger];
//   - [ConfigBase.Handler] filled with [NewDefaultHandler];
//   - [ConfigBase.Name] filled with the test name from [testing.TB];
//   - [ConfigBase.Addr] filled with [LocalhostAnyPort];
//   - [ConfigTLS.TLSConfig] filled with [NewTLSConfig] for [DomainName];
//   - others are set as documented in [dnsserver.ConfigDNS].
//
// addr is the address that can be used to reach that server.
func RunTLSServer(tb testing.TB, c *dnsserver.ConfigTLS) (addr *net.TCPAddr, tlsConf *tls.Config) {
	tb.Helper()

	c = cmp.Or(c, &dnsserver.ConfigTLS{})
	conf := *c
	c = &conf

	confDNS := cmp.Or(conf.DNS, &dnsserver.ConfigDNS{})
	cDNS := *confDNS
	newConfigDNSWithDefaults(tb, &cDNS)
	c.DNS = &cDNS

	if c.TLSConfig == nil {
		c.TLSConfig = NewTLSConfig(DomainName)
	}

	s := dnsserver.NewServerTLS(c)
	require.Equal(tb, dnsserver.ProtoDoT, s.Proto())

	err := runWithRetry(func() (err error) {
		return s.Start(testutil.ContextWithTimeout(tb, testTimeout))
	})
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return s.Shutdown(testutil.ContextWithTimeout(tb, testTimeout))
	})

	return testutil.RequireTypeAssert[*net.TCPAddr](tb, s.LocalTCPAddr()), c.TLSConfig
}

// TestDNSCryptServer is a structure that contains the initialized DNSCrypt
// server and it's properties.
type TestDNSCryptServer struct {
	Srv          *dnsserver.ServerDNSCrypt
	ProviderName string
	ServerAddr   string
	ResolverPk   ed25519.PublicKey
}

// RunDNSCryptServer runs a simple test DNSCrypt server with the specified
// handler for the duration of the test.  It also registers a cleanup function
// to shut down the server.
func RunDNSCryptServer(tb testing.TB, h dnsserver.Handler) (s *TestDNSCryptServer) {
	tb.Helper()

	s = &TestDNSCryptServer{
		ProviderName: DomainName,
	}

	// Generate DNSCrypt configuration for the server
	rc, err := dnscrypt.GenerateResolverConfig(s.ProviderName, nil)
	require.NoError(tb, err)

	cert, err := rc.CreateCert()
	require.NoError(tb, err)

	// Extract the public key (we'll use it for the dnscrypt.Client)
	var privateKey []byte
	privateKey, err = dnscrypt.HexDecodeKey(rc.PrivateKey)
	require.NoError(tb, err)

	pk := ed25519.PrivateKey(privateKey).Public()

	s.ResolverPk = testutil.RequireTypeAssert[ed25519.PublicKey](tb, pk)

	conf := &dnsserver.ConfigDNSCrypt{
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Handler:    h,
			Name:       "test",
			Addr:       "127.0.0.1:0",
		},
		ProviderName: s.ProviderName,
		ResolverCert: cert,
	}

	// Create a new ServerDNSCrypt and run it.
	s.Srv = dnsserver.NewServerDNSCrypt(conf)
	require.Equal(tb, dnsserver.ProtoDNSCrypt, s.Srv.Proto())

	err = runWithRetry(func() error { return s.Srv.Start(context.Background()) })
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return s.Srv.Shutdown(context.Background())
	})

	// Get the address it listens to.  It does not matter which one will be
	// used (UDP or TCP) since we need it in the string format.
	s.ServerAddr = s.Srv.LocalUDPAddr().String()

	return s
}

// RunLocalHTTPSServer runs a simple test HTTP server with the specified
// handler.  addr is the address that can be used to reach that server.  It also
// registers a cleanup function to shut down the server.
func RunLocalHTTPSServer(
	tb testing.TB,
	h dnsserver.Handler,
	tlsConfig *tls.Config,
	nonDNSHandler http.Handler,
) (s *dnsserver.ServerHTTPS) {
	tb.Helper()

	network := dnsserver.NetworkAny
	if tlsConfig == nil {
		network = dnsserver.NetworkTCP
	}

	var tlsConfigH3 *tls.Config
	if tlsConfig != nil {
		tlsConfigH3 = tlsConfig.Clone()

		tlsConfig.NextProtos = dnsserver.NextProtoDoH
		tlsConfigH3.NextProtos = dnsserver.NextProtoDoH3
	}

	conf := &dnsserver.ConfigHTTPS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Handler:    h,
			Network:    network,
			Name:       "test",
			Addr:       "127.0.0.1:0",
		},
		TLSConfDefault: tlsConfig,
		TLSConfH3:      tlsConfigH3,
		NonDNSHandler:  nonDNSHandler,
	}

	s = dnsserver.NewServerHTTPS(conf)
	require.Equal(tb, dnsserver.ProtoDoH, s.Proto())

	servicetest.RequireRun(tb, s, testTimeout)

	return s
}

// RunLocalQUICServer runs a simple test HTTP server with the specified handler.
// addr is the address that can be used to reach that server.  It also registers
// a cleanup function to shut down the server.
func RunLocalQUICServer(
	tb testing.TB,
	h dnsserver.Handler,
	tlsConfig *tls.Config,
) (addr *net.UDPAddr) {
	tb.Helper()

	conf := &dnsserver.ConfigQUIC{
		TLSConfig: tlsConfig,
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Handler:    h,
			Name:       "test",
			Addr:       "127.0.0.1:0",
		},
	}

	s := dnsserver.NewServerQUIC(conf)
	require.Equal(tb, dnsserver.ProtoDoQ, s.Proto())

	servicetest.RequireRun(tb, s, testTimeout)

	return testutil.RequireTypeAssert[*net.UDPAddr](tb, s.LocalUDPAddr())
}

// runWithRetry runs exec func and retries in case of address already in use
// error.
func runWithRetry(exec func() error) (err error) {
	err = exec()
	if err != nil {
		if errorIsAddrInUse(err) {
			// Give system time to release sockets.
			time.Sleep(200 * time.Millisecond)

			err = exec()
			if err != nil {
				err = fmt.Errorf("after one retry: %w", err)
			}
		}
	}

	return err
}
