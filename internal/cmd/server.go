package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// toInternal returns the configuration of DNS servers for a single server
// group.  srvs and other parts of the configuration must be valid.
func (srvs servers) toInternal(
	ctx context.Context,
	btdMgr *bindtodevice.Manager,
	tlsMgr tlsconfig.Manager,
	ratelimitConf *rateLimitConfig,
	dnsConf *dnsConfig,
	certNames []agd.CertificateName,
	deviceDomains []string,
) (dnsSrvs []*agd.Server, err error) {
	dnsSrvs = make([]*agd.Server, 0, len(srvs))
	for i, srv := range srvs {
		var dnsSrv *agd.Server
		dnsSrv, err = srv.toInternal(
			ctx,
			tlsMgr,
			btdMgr,
			ratelimitConf,
			dnsConf,
			certNames,
			deviceDomains,
		)
		if err != nil {
			return nil, fmt.Errorf("server %q: at index %d: %w", srv.Name, i, err)
		}

		dnsSrvs = append(dnsSrvs, dnsSrv)
	}

	return dnsSrvs, nil
}

// toInternal returns the configuration for a single server.  tlsMgr, btdMgr,
// ratelimitConf, and dnsConf must not be nil, certNames items must be valid,
// deviceDomains items must be a valid domain names.
func (s *server) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
	btdMgr *bindtodevice.Manager,
	ratelimitConf *rateLimitConfig,
	dnsConf *dnsConfig,
	certNames []agd.CertificateName,
	deviceDomains []string,
) (dnsSrv *agd.Server, err error) {
	var bindData []*agd.ServerBindData
	bindData, err = s.bindData(btdMgr)
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		return nil, err
	}

	name := agd.ServerName(s.Name)
	dnsSrv = &agd.Server{
		Name:            name,
		ReadTimeout:     time.Duration(dnsConf.ReadTimeout),
		WriteTimeout:    time.Duration(dnsConf.WriteTimeout),
		LinkedIPEnabled: s.LinkedIPEnabled,
		Protocol:        s.Protocol.toInternal(),
	}
	dnsSrv.SetBindData(bindData)

	err = setProtoConfig(ctx, dnsSrv, s, dnsConf, ratelimitConf, tlsMgr, certNames, deviceDomains)
	if err != nil {
		return nil, fmt.Errorf("setting protocol-specific configuration: %w", err)
	}

	return dnsSrv, nil
}

// setProtoConfig sets the protocol-specific configuration to dnsSrv.
func setProtoConfig(
	ctx context.Context,
	dnsSrv *agd.Server,
	s *server,
	dnsConf *dnsConfig,
	ratelimitConf *rateLimitConfig,
	tlsMgr tlsconfig.Manager,
	certNames []agd.CertificateName,
	deviceDomains []string,
) (err error) {
	switch dnsSrv.Protocol {
	case agd.ProtoDNS:
		dnsSrv.TCPConf = &agd.TCPConfig{
			IdleTimeout:        time.Duration(dnsConf.TCPIdleTimeout),
			MaxPipelineCount:   ratelimitConf.TCP.MaxPipelineCount,
			MaxPipelineEnabled: ratelimitConf.TCP.Enabled,
		}

		dnsSrv.UDPConf = &agd.UDPConfig{
			// #nosec G115 -- The value has already been validated in
			// [dnsConfig.Validate].
			MaxRespSize: uint16(dnsConf.MaxUDPResponseSize.Bytes()),
		}
	case agd.ProtoDNSCrypt:
		var dcConf *agd.DNSCryptConfig
		dcConf, err = s.DNSCrypt.toInternal()
		if err != nil {
			return fmt.Errorf("dnscrypt: %w", err)
		}

		dnsSrv.DNSCrypt = dcConf
	default:
		dnsSrv.TCPConf = &agd.TCPConfig{
			IdleTimeout:        time.Duration(dnsConf.TCPIdleTimeout),
			MaxPipelineCount:   ratelimitConf.TCP.MaxPipelineCount,
			MaxPipelineEnabled: ratelimitConf.TCP.Enabled,
		}

		dnsSrv.QUICConf = &agd.QUICConfig{
			MaxStreamsPerPeer: ratelimitConf.QUIC.MaxStreamsPerPeer,
			QUICLimitsEnabled: ratelimitConf.QUIC.Enabled,
		}

		dnsSrv.TLS = newTLSConfig(dnsSrv, tlsMgr, deviceDomains, s)
		err = bindTLSNames(ctx, dnsSrv, tlsMgr, certNames)
		if err != nil {
			// Don't wrap the error, since it's informative enough as is.
			return err
		}
	}

	return nil
}

// bindTLSNames binds the server to the specified certificate names in the TLS
// manager.
func bindTLSNames(
	ctx context.Context,
	s *agd.Server,
	tlsMgr tlsconfig.Manager,
	names []agd.CertificateName,
) (err error) {
	var errs []error
	for _, pref := range s.BindDataPrefixes() {
		for _, name := range names {
			err = tlsMgr.Bind(ctx, name, pref)
			if err != nil {
				errs = append(errs, fmt.Errorf("binding %q to %s: %w", name, pref, err))
			}
		}
	}

	return errors.Join(errs...)
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

// validateWithTLS returns an error if the configuration is invalid.
func (srvs servers) validateWithTLS() (needsTLS bool, err error) {
	if len(srvs) == 0 {
		return false, errors.ErrEmptyValue
	}

	var errs []error
	names := container.NewMapSet[string]()
	for i, s := range srvs {
		err = s.Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("at index %d: %w", i, err))

			continue
		}

		if names.Has(s.Name) {
			errs = append(errs, fmt.Errorf(
				"at index %d: name: %w: %q",
				i,
				errors.ErrDuplicated,
				s.Name,
			))

			continue
		}

		names.Add(s.Name)

		needsTLS = needsTLS || s.Protocol.needsTLS()
	}

	return needsTLS, errors.Join(errs...)
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
var _ validate.Interface = serverProto("")

// Validate implements the [validate.Interface] interface for serverProto.
func (p serverProto) Validate() (err error) {
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
var _ validate.Interface = (*server)(nil)

// Validate implements the [validate.Interface] interface for *server.
func (s *server) Validate() (err error) {
	if s == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmpty("name", s.Name),
	}

	err = s.validateBindData()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		errs = append(errs, err)
	}

	err = s.Protocol.Validate()
	if err != nil {
		errs = append(errs, fmt.Errorf("protocol: %w", err))
	}

	err = s.DNSCrypt.validateForProtocol(s.Protocol)
	if err != nil {
		errs = append(errs, fmt.Errorf("dnscrypt: %w", err))
	}

	return errors.Join(errs...)
}

// validateBindData returns an error if the server's binding data aren't valid.
func (s *server) validateBindData() (err error) {
	bindAddrsSet, bindIfacesSet := len(s.BindAddresses) > 0, len(s.BindInterfaces) > 0
	if bindAddrsSet {
		if bindIfacesSet {
			return errors.Error("bind_addresses and bind_interfaces cannot both be set")
		}

		// Don't wrap the error, because it's informative enough as is.
		return validateBindAddrs(s.BindAddresses)
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

	return validate.Slice("bind_interfaces", s.BindInterfaces)
}

// validateBindAddrs returns an error if any of addrs isn't valid.
//
// TODO(a.garipov): Merge with [validateNonNilIPs].
func validateBindAddrs(addrs []netip.AddrPort) (err error) {
	var errs []error
	for i, a := range addrs {
		if !a.IsValid() {
			errs = append(errs, fmt.Errorf("bind_addresses: at index %d: invalid addr", i))
		}
	}

	return errors.Join(errs...)
}

// serverBindInterface contains the data for a network interface binding.
type serverBindInterface struct {
	ID      bindtodevice.ID `yaml:"id"`
	Subnets []netip.Prefix  `yaml:"subnets"`
}

// type check
var _ validate.Interface = (*serverBindInterface)(nil)

// Validate implements the [validate.Interface] interface for *serverBindInterface.
func (c *serverBindInterface) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmpty("id", c.ID),
		validate.NotEmptySlice("subnets", c.Subnets),
	}

	set := container.NewMapSet[netip.Prefix]()
	for i, subnet := range c.Subnets {
		if !subnet.IsValid() {
			errs = append(errs, fmt.Errorf("subnets: at index %d: bad subnet", i))

			continue
		}

		if set.Has(subnet) {
			errs = append(errs, fmt.Errorf(
				"subnets: at index %d: %w: %s",
				i,
				errors.ErrDuplicated,
				subnet,
			))

			continue
		}

		set.Add(subnet)
	}

	return errors.Join(errs...)
}
