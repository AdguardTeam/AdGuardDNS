package dnsservertest

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/ameshkov/dnscrypt/v2"
)

// RunLocalDNSServer runs a simple test server with the specified handler.  addr
// is the address that can be used to reach that server.
func RunLocalDNSServer(
	h dnsserver.Handler,
	proto dnsserver.Protocol,
) (s *dnsserver.ServerDNS, addr string, err error) {
	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Proto:   proto,
			Handler: h,
		},
	}
	s = dnsserver.NewServerDNS(conf)

	err = s.Start(context.Background())
	if err != nil {
		return nil, "", err
	}

	return s, s.LocalAddr().String(), nil
}

// DNSServer represents a plain DNS server that listens to both TCP and UDP.
type DNSServer struct {
	Addr   string
	SrvTCP *dnsserver.ServerDNS
	SrvUDP *dnsserver.ServerDNS
}

// Shutdown stops both servers
func (s *DNSServer) Shutdown(ctx context.Context) (err error) {
	err = s.SrvUDP.Shutdown(ctx)
	if err != nil {
		return err
	}
	return s.SrvTCP.Shutdown(ctx)
}

// RunDNSServer runs a test DNS server with the specified handler.  Actually, it
// runs two DNS servers, one with dnsserver.ProtoDNSUDP and the other one with
// dnsserver.ProtoDNSTCP, both of which use the same port.
func RunDNSServer(h dnsserver.Handler) (s *DNSServer, err error) {
	s = &DNSServer{}

	// First let's run the TCP server
	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test_tcp",
			Addr:    "127.0.0.1:0",
			Proto:   dnsserver.ProtoDNSTCP,
			Handler: h,
		},
	}
	s.SrvTCP = dnsserver.NewServerDNS(conf)
	err = s.SrvTCP.Start(context.Background())
	if err != nil {
		return nil, err
	}

	// Now let's get the port that it uses
	port := s.SrvTCP.LocalAddr().(*net.TCPAddr).Port
	s.Addr = fmt.Sprintf("127.0.0.1:%d", port)

	// Now we can run the UDP server
	conf = dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test_udp",
			Addr:    s.Addr,
			Proto:   dnsserver.ProtoDNSUDP,
			Handler: h,
		},
	}
	s.SrvUDP = dnsserver.NewServerDNS(conf)
	err = s.SrvUDP.Start(context.Background())
	if err != nil {
		return nil, err
	}

	return s, nil
}

// RunLocalTLSServer runs a simple test server with the specified handler
// returns the address that can be used to reach that server
func RunLocalTLSServer(
	h dnsserver.Handler,
	tlsConfig *tls.Config,
) (s *dnsserver.ServerTLS, addr *net.TCPAddr, err error) {
	conf := dnsserver.ConfigTLS{
		ConfigDNS: dnsserver.ConfigDNS{
			ConfigBase: dnsserver.ConfigBase{
				Name:    "test",
				Addr:    "127.0.0.1:0",
				Proto:   dnsserver.ProtoDoT,
				Handler: h,
			},
		},
		TLSConfig: tlsConfig,
	}

	s = dnsserver.NewServerTLS(conf)
	if s.Proto() != dnsserver.ProtoDoT {
		return nil, nil, errors.Error("invalid protocol")
	}
	err = s.Start(context.Background())
	if err != nil {
		return nil, nil, err
	}

	addr, ok := s.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid listen addr: %s", addr)
	}

	return s, addr, nil
}

// TestDNSCryptServer is a structure that contains the initialized DNSCrypt
// server and it's properties.
type TestDNSCryptServer struct {
	Srv          *dnsserver.ServerDNSCrypt
	ProviderName string
	ResolverPk   ed25519.PublicKey
	ServerAddr   string
}

// RunLocalDNSCryptServer runs a simple test DNSCrypt server with the specified
// handler.  Returns the address that can be used to reach that server.
func RunLocalDNSCryptServer(
	h dnsserver.Handler,
	network dnsserver.Network,
) (s *TestDNSCryptServer, err error) {
	s = &TestDNSCryptServer{
		ProviderName: "example.org",
	}

	// Generate DNSCrypt configuration for the server
	var rc dnscrypt.ResolverConfig
	rc, err = dnscrypt.GenerateResolverConfig(s.ProviderName, nil)
	if err != nil {
		return nil, err
	}
	var cert *dnscrypt.Cert
	cert, err = rc.CreateCert()
	if err != nil {
		return nil, err
	}

	// Extract the public key (we'll use it for the dnscrypt.Client)
	var privateKey []byte
	privateKey, err = dnscrypt.HexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, err
	}
	resolverPk, ok := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.Error("could not create a private key")
	}
	s.ResolverPk = resolverPk

	proto := dnsserver.ProtoDNSCryptUDP
	if network != dnsserver.NetworkUDP {
		proto = dnsserver.ProtoDNSCryptTCP
	}

	conf := dnsserver.ConfigDNSCrypt{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Proto:   proto,
			Handler: h,
		},
		DNSCryptProviderName: s.ProviderName,
		DNSCryptResolverCert: cert,
	}

	// Create a new ServerDNSCrypt and run it
	s.Srv = dnsserver.NewServerDNSCrypt(conf)
	err = s.Srv.Start(context.Background())
	if err != nil {
		return nil, err
	}

	// Get the address it listens to
	addr := s.Srv.LocalAddr()
	if addr == nil {
		return nil, errors.Error("wrong address")
	}

	switch v := addr.(type) {
	case *net.UDPAddr:
		s.ServerAddr = fmt.Sprintf("127.0.0.1:%d", v.Port)
	case *net.TCPAddr:
		s.ServerAddr = fmt.Sprintf("127.0.0.1:%d", v.Port)
	default:
		return nil, fmt.Errorf("wrong address %v", addr)
	}

	return s, nil
}

// RunLocalHTTPSServer runs a simple test HTTP server with the specified handler.
// addr is the address that can be used to reach that server.
func RunLocalHTTPSServer(
	h dnsserver.Handler,
	tlsConfig *tls.Config,
	nonDNSHandler http.Handler,
) (s *dnsserver.ServerHTTPS, addr *net.TCPAddr, err error) {
	conf := dnsserver.ConfigHTTPS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Proto:   dnsserver.ProtoDoH,
			Handler: h,
		},
		TLSConfig:     tlsConfig,
		NonDNSHandler: nonDNSHandler,
	}

	s = dnsserver.NewServerHTTPS(conf)
	if s.Proto() != dnsserver.ProtoDoH {
		return nil, nil, errors.Error("invalid protocol")
	}

	err = s.Start(context.Background())
	if err != nil {
		return nil, nil, err
	}

	var ok bool
	addr, ok = s.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid listen addr: %s", addr)
	}

	return s, addr, nil
}

// RunLocalQUICServer runs a simple test HTTP server with the specified handler.
// addr is the address that can be used to reach that server.
func RunLocalQUICServer(
	h dnsserver.Handler,
	tlsConfig *tls.Config,
) (s *dnsserver.ServerQUIC, addr *net.UDPAddr, err error) {
	conf := dnsserver.ConfigQUIC{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Proto:   dnsserver.ProtoDoQ,
			Handler: h,
		},
		TLSConfig: tlsConfig,
	}

	s = dnsserver.NewServerQUIC(conf)
	if s.Proto() != dnsserver.ProtoDoQ {
		return nil, nil, errors.Error("invalid protocol")
	}

	err = s.Start(context.Background())
	if err != nil {
		return nil, nil, err
	}

	addr, ok := s.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid listen addr: %s", addr)
	}

	return s, addr, nil
}
