package cmd

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Server configuration

// toInternal returns the configuration of DNS servers for a single server
// group.  srvs is assumed to be valid.
func (srvs servers) toInternal(tlsConfig *agd.TLS) (dnsSrvs []*agd.Server, err error) {
	dnsSrvs = make([]*agd.Server, 0, len(srvs))
	for _, srv := range srvs {
		bindData := srv.bindData()
		name := agd.ServerName(srv.Name)
		switch p := srv.Protocol; p {
		case srvProtoDNS:
			dnsSrvs = append(dnsSrvs, &agd.Server{
				Name:            name,
				BindData:        bindData,
				Protocol:        agd.ProtoDNS,
				LinkedIPEnabled: srv.LinkedIPEnabled,
			})
		case srvProtoDNSCrypt:
			var dcConf *agd.DNSCryptConfig
			dcConf, err = srv.DNSCrypt.toInternal()
			if err != nil {
				return nil, fmt.Errorf("server %q: dnscrypt: %w", srv.Name, err)
			}

			dnsSrvs = append(dnsSrvs, &agd.Server{
				DNSCrypt:        dcConf,
				Name:            name,
				BindData:        bindData,
				Protocol:        agd.ProtoDNSCrypt,
				LinkedIPEnabled: srv.LinkedIPEnabled,
			})
		default:
			tlsConf := tlsConfig.Conf.Clone()

			// Attach the functions that will count TLS handshake metrics.
			tlsConf.GetConfigForClient = metrics.TLSMetricsBeforeHandshake(string(srv.Protocol))
			tlsConf.VerifyConnection = metrics.TLSMetricsAfterHandshake(
				string(srv.Protocol),
				srv.Name,
				tlsConfig.DeviceIDWildcards,
				tlsConf.Certificates,
			)

			dnsSrvs = append(dnsSrvs, &agd.Server{
				TLS:             tlsConf,
				Name:            name,
				BindData:        bindData,
				Protocol:        p.toInternal(),
				LinkedIPEnabled: srv.LinkedIPEnabled,
			})
		}
	}

	return dnsSrvs, nil
}

// servers is a slice of server settings.  A valid instance of servers has no
// nil items.
type servers []*server

// validate returns an error if the configuration is invalid.
func (srvs servers) validate() (needsTLS bool, err error) {
	if len(srvs) == 0 {
		return false, errors.Error("no servers")
	}

	names := stringutil.NewSet()
	for i, s := range srvs {
		if s == nil {
			return false, fmt.Errorf("at index %d: no server", i)
		}

		err = s.validate()
		if err != nil {
			return false, fmt.Errorf("at index %d: %w", i, err)
		}

		if names.Has(s.Name) {
			return false, fmt.Errorf("at index %d: duplicate name %q", i, s.Name)
		}

		names.Add(s.Name)

		needsTLS = needsTLS || s.Protocol.needsTLS()
	}

	return needsTLS, nil
}

// serverProto is the type for the server protocols in the on-disk
// configuration.
type serverProto string

// Valid protocol values in the on-disk configuration file.
const (
	srvProtoDNS      serverProto = "dns"
	srvProtoDNSCrypt serverProto = "dnscrypt"
	srvProtoHTTPS    serverProto = "https"
	srvProtoQUIC     serverProto = "quic"
	srvProtoTLS      serverProto = "tls"
)

// needsTLS returns true if a server with this protocol requires a TLS
// configuration.
func (p serverProto) needsTLS() (ok bool) {
	return p == srvProtoHTTPS || p == srvProtoQUIC || p == srvProtoTLS
}

// toInternal returns the equivalent agd.Protocol value if there is one.  If
// there is no such value, it returns agd.ProtoInvalid.
func (p serverProto) toInternal() (sp agd.Protocol) {
	switch p {
	case srvProtoHTTPS:
		return agd.ProtoDoH
	case srvProtoQUIC:
		return agd.ProtoDoQ
	case srvProtoTLS:
		return agd.ProtoDoT
	default:
		return agd.ProtoInvalid
	}
}

// validate returns an error if the configuration is invalid.
func (p serverProto) validate() (err error) {
	switch p {
	case srvProtoDNS,
		srvProtoDNSCrypt,
		srvProtoHTTPS,
		srvProtoQUIC,
		srvProtoTLS:
		return nil
	default:
		return fmt.Errorf("bad protocol: %q", p)
	}
}

// server defines the DNS server settings.
type server struct {
	// DNSCrypt are the DNSCrypt settings for this server, if any.
	DNSCrypt *dnsCryptConfig `yaml:"dnscrypt"`

	// Name is the unique name of the server.
	Name string `yaml:"name"`

	// Protocol is the protocol of the server.
	Protocol serverProto `yaml:"protocol"`

	// BindAddresses are addresses this server binds to.
	BindAddresses []netip.AddrPort `yaml:"bind_addresses"`

	// LinkedIPEnabled shows if the linked IP addresses should be used to detect
	// profiles on this server.
	LinkedIPEnabled bool `yaml:"linked_ip_enabled"`
}

// bindData returns the socket binding data for this server.
func (s *server) bindData() (bindData []*agd.ServerBindData) {
	addrs := s.BindAddresses
	bindData = make([]*agd.ServerBindData, 0, len(addrs))
	for _, addr := range addrs {
		bindData = append(bindData, &agd.ServerBindData{
			AddrPort: addr,
		})
	}

	// TODO(a.garipov): Support bind_interfaces.

	return bindData
}

// validate returns an error if the configuration is invalid.
func (s *server) validate() (err error) {
	switch {
	case s == nil:
		return errNilConfig
	case s.Name == "":
		return errors.Error("no name")
	case len(s.BindAddresses) == 0:
		return errors.Error("no bind_addresses")
	}

	err = validateAddrs(s.BindAddresses)
	if err != nil {
		return fmt.Errorf("bind_addresses: %w", err)
	}

	err = s.Protocol.validate()
	if err != nil {
		return fmt.Errorf("protocol: %w", err)
	}

	err = s.DNSCrypt.validate(s.Protocol)
	if err != nil {
		return fmt.Errorf("dnscrypt: %w", err)
	}

	return nil
}
