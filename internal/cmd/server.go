package cmd

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
)

// toInternal returns the configuration of DNS servers for a single server
// group.  srvs and other parts of the configuration must be valid.
func (srvs servers) toInternal(
	btdMgr *bindtodevice.Manager,
	tlsMgr tlsconfig.Manager,
	ratelimitConf *rateLimitConfig,
	dnsConf *dnsConfig,
	deviceDomains []string,
) (dnsSrvs []*agd.Server, err error) {
	dnsSrvs = make([]*agd.Server, 0, len(srvs))
	for _, srv := range srvs {
		var bindData []*agd.ServerBindData
		bindData, err = srv.bindData(btdMgr)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", srv.Name, err)
		}

		name := agd.ServerName(srv.Name)
		dnsSrv := &agd.Server{
			Name:            name,
			ReadTimeout:     dnsConf.ReadTimeout.Duration,
			WriteTimeout:    dnsConf.WriteTimeout.Duration,
			LinkedIPEnabled: srv.LinkedIPEnabled,
			Protocol:        srv.Protocol.toInternal(),
		}

		tcpConf := &agd.TCPConfig{
			IdleTimeout:        dnsConf.TCPIdleTimeout.Duration,
			MaxPipelineCount:   ratelimitConf.TCP.MaxPipelineCount,
			MaxPipelineEnabled: ratelimitConf.TCP.Enabled,
		}

		switch dnsSrv.Protocol {
		case agd.ProtoDNS:
			dnsSrv.TCPConf = tcpConf
			dnsSrv.UDPConf = &agd.UDPConfig{
				// #nosec G115 -- The value has already been validated in
				// [dnsConfig.validate].
				MaxRespSize: uint16(dnsConf.MaxUDPResponseSize.Bytes()),
			}
		case agd.ProtoDNSCrypt:
			var dcConf *agd.DNSCryptConfig
			dcConf, err = srv.DNSCrypt.toInternal()
			if err != nil {
				return nil, fmt.Errorf("server %q: dnscrypt: %w", srv.Name, err)
			}

			dnsSrv.DNSCrypt = dcConf
		default:
			dnsSrv.TCPConf = tcpConf
			dnsSrv.QUICConf = &agd.QUICConfig{
				MaxStreamsPerPeer: ratelimitConf.QUIC.MaxStreamsPerPeer,
				QUICLimitsEnabled: ratelimitConf.QUIC.Enabled,
			}

			dnsSrv.TLS = newTLSConfig(dnsSrv, tlsMgr, deviceDomains, srv)
		}

		dnsSrv.SetBindData(bindData)

		dnsSrvs = append(dnsSrvs, dnsSrv)
	}

	return dnsSrvs, nil
}

// newTLSConfig returns the TLS configuration with metrics and ALPs set.
//
// TODO(s.chzhen):  Consider moving to agd package as soon as the import cycle
// is resolved.
func newTLSConfig(
	dnsSrv *agd.Server,
	tlsMgr tlsconfig.Manager,
	deviceDomains []string,
	srv *server,
) (c *agd.TLSConfig) {
	tlsConf := tlsMgr.CloneWithMetrics(string(srv.Protocol), srv.Name, deviceDomains)

	var tlsConfH3 *tls.Config
	switch dnsSrv.Protocol {
	case agd.ProtoDoH:
		tlsConfH3 = tlsMgr.CloneWithMetrics(string(srv.Protocol), srv.Name, deviceDomains)

		tlsConf.NextProtos = slices.Clone(dnsserver.NextProtoDoH)
		tlsConfH3.NextProtos = slices.Clone(dnsserver.NextProtoDoH3)
	case agd.ProtoDoQ:
		tlsConf.NextProtos = slices.Clone(dnsserver.NextProtoDoQ)
	}

	return &agd.TLSConfig{
		Default: tlsConf,
		H3:      tlsConfH3,
	}
}

// servers is a slice of server settings.  A valid instance of servers has no
// nil items.
type servers []*server

// validate returns an error if the configuration is invalid.
func (srvs servers) validate() (needsTLS bool, err error) {
	if len(srvs) == 0 {
		return false, errors.Error("no servers")
	}

	names := container.NewMapSet[string]()
	for i, s := range srvs {
		if s == nil {
			return false, fmt.Errorf("at index %d: no server", i)
		}

		err = s.validate()
		if err != nil {
			return false, fmt.Errorf("at index %d: %w", i, err)
		}

		if names.Has(s.Name) {
			return false, fmt.Errorf("at index %d: name: %w: %q", i, errors.ErrDuplicated, s.Name)
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
// there is no such value, it returns [agd.ProtoInvalid].
func (p serverProto) toInternal() (sp agd.Protocol) {
	switch p {
	case srvProtoDNS:
		return agd.ProtoDNS
	case srvProtoDNSCrypt:
		return agd.ProtoDNSCrypt
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

// type check
var _ validator = serverProto("")

// validate implements the [validator] interface for serverProto.
func (p serverProto) validate() (err error) {
	switch p {
	case srvProtoDNS,
		srvProtoDNSCrypt,
		srvProtoHTTPS,
		srvProtoQUIC,
		srvProtoTLS:
		return nil
	default:
		return fmt.Errorf("protocol: %w: %q", errors.ErrBadEnumValue, p)
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

	// BindAddresses are addresses this server binds to.  If BindAddresses is
	// set, BindInterfaces must not be set.
	BindAddresses []netip.AddrPort `yaml:"bind_addresses"`

	// BindInterfaces are network interface data for this server to bind to.  If
	// BindInterfaces is set, BindAddresses must not be set.
	BindInterfaces []*serverBindInterface `yaml:"bind_interfaces"`

	// LinkedIPEnabled shows if the linked IP addresses should be used to detect
	// profiles on this server.
	LinkedIPEnabled bool `yaml:"linked_ip_enabled"`
}

// bindData returns the socket binding data for this server.
func (s *server) bindData(
	btdMgr *bindtodevice.Manager,
) (bindData []*agd.ServerBindData, err error) {
	if addrs := s.BindAddresses; len(addrs) > 0 {
		bindData = make([]*agd.ServerBindData, 0, len(addrs))
		for _, addr := range addrs {
			bindData = append(bindData, &agd.ServerBindData{
				AddrPort: addr,
			})
		}

		return bindData, nil
	}

	if btdMgr == nil {
		err = errors.Error("bind_interfaces are only supported when interface_listeners are set")

		return nil, err
	}

	ifaces := s.BindInterfaces
	bindData = make([]*agd.ServerBindData, 0, len(ifaces))
	for i, iface := range ifaces {
		for j, subnet := range iface.Subnets {
			var lc *bindtodevice.ListenConfig
			lc, err = btdMgr.ListenConfig(iface.ID, subnet)
			if err != nil {
				const errStr = "bind_interface at index %d: subnet at index %d: %w"

				return nil, fmt.Errorf(errStr, i, j, err)
			}

			bindData = append(bindData, &agd.ServerBindData{
				ListenConfig: lc,
				PrefixAddr:   lc.Addr(),
			})
		}
	}

	return bindData, nil
}

// type check
var _ validator = (*server)(nil)

// validate implements the [validator] interface for *server.
func (s *server) validate() (err error) {
	switch {
	case s == nil:
		return errors.ErrNoValue
	case s.Name == "":
		return fmt.Errorf("name: %w", errors.ErrEmptyValue)
	}

	err = s.validateBindData()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
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

// validateBindData returns an error if the server's binding data aren't valid.
func (s *server) validateBindData() (err error) {
	bindAddrsSet, bindIfacesSet := len(s.BindAddresses) > 0, len(s.BindInterfaces) > 0
	if bindAddrsSet {
		if bindIfacesSet {
			return errors.Error("bind_addresses and bind_interfaces cannot both be set")
		}

		err = validateAddrs(s.BindAddresses)
		if err != nil {
			return fmt.Errorf("bind_addresses: %w", err)
		}

		return nil
	}

	if !bindIfacesSet {
		return errors.Error("neither bind_addresses nor bind_interfaces is set")
	}

	if s.Protocol != srvProtoDNS {
		return fmt.Errorf(
			"bind_interfaces: only supported for protocol %q, got %q",
			srvProtoDNS,
			s.Protocol,
		)
	}

	for i, bindIface := range s.BindInterfaces {
		err = bindIface.validate()
		if err != nil {
			return fmt.Errorf("bind_interfaces: at index %d: %w", i, err)
		}
	}

	return nil
}

// serverBindInterface contains the data for a network interface binding.
type serverBindInterface struct {
	ID      bindtodevice.ID `yaml:"id"`
	Subnets []netip.Prefix  `yaml:"subnets"`
}

// type check
var _ validator = (*serverBindInterface)(nil)

// validate implements the [validator] interface for *serverBindInterface.
func (c *serverBindInterface) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.ID == "":
		return fmt.Errorf("id: %w", errors.ErrEmptyValue)
	case len(c.Subnets) == 0:
		return fmt.Errorf("subnets: %w", errors.ErrEmptyValue)
	default:
		// Go on.
	}

	set := container.NewMapSet[netip.Prefix]()
	for i, subnet := range c.Subnets {
		if !subnet.IsValid() {
			return fmt.Errorf("subnets: at index %d: bad subnet", i)
		}

		if set.Has(subnet) {
			return fmt.Errorf("subnets: at index %d: %w: %s", i, errors.ErrDuplicated, subnet)
		}

		set.Add(subnet)
	}

	return nil
}
