package dnsservertest

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// RunDNSServer runs a simple test server with the specified handler for the
// duration of the test.  It also registers a cleanup function that stops the
// server.  addr is the address that can be used to reach that server.
//
// TODO(a.garipov): s seems to only be used for LocalUDPAddr.  Perhaps, only
// return it?
func RunDNSServer(t testing.TB, h dnsserver.Handler) (s *dnsserver.ServerDNS, addr string) {
	t.Helper()

	conf := &dnsserver.ConfigDNS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    h,
		},
		MaxUDPRespSize: dns.MaxMsgSize,
	}
	s = dnsserver.NewServerDNS(conf)
	require.Equal(t, dnsserver.ProtoDNS, s.Proto())

	err := runWithRetry(func() error { return s.Start(context.Background()) })
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return s.Shutdown(context.Background())
	})

	localAddr := s.LocalTCPAddr()
	if localAddr == nil {
		localAddr = s.LocalUDPAddr()
	}

	return s, localAddr.String()
}

// RunTLSServer runs a simple test server with the specified handler for the
// duration of the test.  It also registers a cleanup function that stops the
// server.  addr is the address that can be used to reach that server.
func RunTLSServer(t testing.TB, h dnsserver.Handler, tlsConfig *tls.Config) (addr *net.TCPAddr) {
	t.Helper()

	conf := &dnsserver.ConfigTLS{
		DNS: &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{
				BaseLogger: slogutil.NewDiscardLogger(),
				Name:       "test",
				Addr:       "127.0.0.1:0",
				Handler:    h,
			},
		},
		TLSConfig: tlsConfig,
	}

	s := dnsserver.NewServerTLS(conf)
	require.Equal(t, dnsserver.ProtoDoT, s.Proto())

	err := runWithRetry(func() error { return s.Start(context.Background()) })
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return s.Shutdown(context.Background())
	})

	return testutil.RequireTypeAssert[*net.TCPAddr](t, s.LocalTCPAddr())
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
// that stops the server.
func RunDNSCryptServer(t testing.TB, h dnsserver.Handler) (s *TestDNSCryptServer) {
	t.Helper()

	s = &TestDNSCryptServer{
		ProviderName: "example.org",
	}

	// Generate DNSCrypt configuration for the server
	rc, err := dnscrypt.GenerateResolverConfig(s.ProviderName, nil)
	require.NoError(t, err)

	cert, err := rc.CreateCert()
	require.NoError(t, err)

	// Extract the public key (we'll use it for the dnscrypt.Client)
	var privateKey []byte
	privateKey, err = dnscrypt.HexDecodeKey(rc.PrivateKey)
	require.NoError(t, err)

	pk := ed25519.PrivateKey(privateKey).Public()

	s.ResolverPk = testutil.RequireTypeAssert[ed25519.PublicKey](t, pk)

	conf := &dnsserver.ConfigDNSCrypt{
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    h,
		},
		ProviderName: s.ProviderName,
		ResolverCert: cert,
	}

	// Create a new ServerDNSCrypt and run it.
	s.Srv = dnsserver.NewServerDNSCrypt(conf)
	require.Equal(t, dnsserver.ProtoDNSCrypt, s.Srv.Proto())

	err = runWithRetry(func() error { return s.Srv.Start(context.Background()) })
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return s.Srv.Shutdown(context.Background())
	})

	// Get the address it listens to.  It does not matter which one will be
	// used (UDP or TCP) since we need it in the string format.
	s.ServerAddr = s.Srv.LocalUDPAddr().String()

	return s
}

// RunLocalHTTPSServer runs a simple test HTTP server with the specified
// handler.  addr is the address that can be used to reach that server.
func RunLocalHTTPSServer(
	h dnsserver.Handler,
	tlsConfig *tls.Config,
	nonDNSHandler http.Handler,
) (s *dnsserver.ServerHTTPS, err error) {
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
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    h,
			Network:    network,
		},
		TLSConfDefault: tlsConfig,
		TLSConfH3:      tlsConfigH3,
		NonDNSHandler:  nonDNSHandler,
	}

	s = dnsserver.NewServerHTTPS(conf)
	if s.Proto() != dnsserver.ProtoDoH {
		return nil, errors.Error("invalid protocol")
	}

	err = s.Start(context.Background())
	if err != nil {
		return nil, err
	}

	return s, nil
}

// RunLocalQUICServer runs a simple test HTTP server with the specified handler.
// addr is the address that can be used to reach that server.
func RunLocalQUICServer(
	h dnsserver.Handler,
	tlsConfig *tls.Config,
) (s *dnsserver.ServerQUIC, addr *net.UDPAddr, err error) {
	conf := &dnsserver.ConfigQUIC{
		TLSConfig: tlsConfig,
		Base: &dnsserver.ConfigBase{
			BaseLogger: slogutil.NewDiscardLogger(),
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    h,
		},
	}

	s = dnsserver.NewServerQUIC(conf)
	if s.Proto() != dnsserver.ProtoDoQ {
		return nil, nil, errors.Error("invalid protocol")
	}

	err = s.Start(context.Background())
	if err != nil {
		return nil, nil, err
	}

	addr, ok := s.LocalUDPAddr().(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid listen addr: %T(%[1]v)", s.LocalUDPAddr())
	}

	return s, addr, nil
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
