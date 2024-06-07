package cmd

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Discovery Of Designated Resolvers (DDR) configuration

// ddrConfig is the configuration for a server group's DDR handler.
type ddrConfig struct {
	// DeviceRecords are used to respond to DDR queries from recognized devices.
	// The keys of the map are device ID wildcards.
	DeviceRecords map[string]*ddrRecord `yaml:"device_records"`

	// PublicRecords are used to respond to DDR queries from unrecognized
	// devices.  The keys of the map are the public domain names.
	PublicRecords map[string]*ddrRecord `yaml:"public_records"`

	// Enabled shows if DDR queries are processed.  If it is false, DDR queries
	// receive an NXDOMAIN response.
	Enabled bool `yaml:"enabled"`
}

// toInternal returns the DDR configuration.  messages must not be nil.  c is
// assumed to be valid.
func (c *ddrConfig) toInternal(msgs *dnsmsg.Constructor) (conf *agd.DDR) {
	conf = &agd.DDR{
		Enabled: c.Enabled,
	}

	conf.DeviceTargets, conf.DeviceRecordTemplates = ddrRecsToSVCBTmpls(msgs, c.DeviceRecords)
	conf.PublicTargets, conf.PublicRecordTemplates = ddrRecsToSVCBTmpls(msgs, c.PublicRecords)

	return conf
}

// ddrRecsToSVCBTmpls converts a target to record mapping into DDR SVCB record
// templates.
func ddrRecsToSVCBTmpls(
	msgs *dnsmsg.Constructor,
	records map[string]*ddrRecord,
) (targets *container.MapSet[string], tmpls []*dns.SVCB) {
	targets = container.NewMapSet[string]()
	for target, r := range records {
		target = strings.TrimPrefix(target, "*.")
		targets.Add(target)
		tmpls = appendDDRSVCBTmpls(tmpls, msgs, r, target)
	}

	slices.SortStableFunc(tmpls, func(a, b *dns.SVCB) (res int) {
		return cmp.Compare(a.Priority, b.Priority)
	})

	return targets, tmpls
}

// appendDDRSVCBTmpls creates and appends new SVCB record templates to recs for
// each protocol port that is not zero.
func appendDDRSVCBTmpls(
	recs []*dns.SVCB,
	msgs *dnsmsg.Constructor,
	r *ddrRecord,
	target string,
) (result []*dns.SVCB) {
	protoPorts := []struct {
		proto agd.Protocol
		port  uint16
	}{{
		proto: agd.ProtoDoH,
		port:  r.HTTPSPort,
	}, {
		proto: agd.ProtoDoT,
		port:  r.TLSPort,
	}, {
		proto: agd.ProtoDoQ,
		port:  r.QUICPort,
	}}

	var prio uint16
	for _, pp := range protoPorts {
		if pp.port != 0 {
			prio++

			recs = append(recs, msgs.NewDDRTemplate(
				pp.proto,
				target,
				r.DoHPath,
				r.IPv4Hints,
				r.IPv6Hints,
				pp.port,
				prio,
			))
		}
	}

	return recs
}

// validate returns an error if the DDR configuration is invalid.
func (c *ddrConfig) validate() (err error) {
	if c == nil {
		return errNilConfig
	}

	for wildcard, r := range c.DeviceRecords {
		if !strings.HasPrefix(wildcard, "*.") {
			return fmt.Errorf("device_records: record for wildcard %q: not a wildcard", wildcard)
		}

		domainSuf := wildcard[2:]
		err = errors.Join(netutil.ValidateHostname(domainSuf), r.validate())
		if err != nil {
			return fmt.Errorf("device_records: wildcard %q: %w", wildcard, err)
		}
	}

	for domain, r := range c.PublicRecords {
		err = errors.Join(netutil.ValidateHostname(domain), r.validate())
		if err != nil {
			return fmt.Errorf("public_records: domain %q: %w", domain, err)
		}
	}

	return nil
}

// ddrRecord is a DDR record template for responses to DDR queries from both
// recognized and unrecognized devices.
type ddrRecord struct {
	// DoHPath is the optional path template for the DoH DDR SVCB records.
	DoHPath string `yaml:"doh_path"`

	// IPv4Hints are the optional hints about the IPv4-addresses of the server.
	IPv4Hints []netip.Addr `yaml:"ipv4_hints"`

	// IPv6Hints are the optional hints about the IPv6-addresses of the server.
	IPv6Hints []netip.Addr `yaml:"ipv6_hints"`

	// HTTPSPort is the port to use in DDR responses about the DoH resolver.  If
	// HTTPSPort is zero, the DoH resolver address is not included into the
	// answer.  A non-zero HTTPSPort should not be the same as TLSPort.
	HTTPSPort uint16 `yaml:"https_port"`

	// QUICPort is the port to use in DDR responses about the DoQ resolver.  If
	// QUICPort is zero, the DoQ resolver address is not included into the
	// answer.
	QUICPort uint16 `yaml:"quic_port"`

	// TLSPort is the port to use in DDR responses about the DoT resolver.  If
	// TLSPort is zero, the DoT resolver address is not included into the
	// answer.  A non-zero TLSPort should not be the same as HTTPSPort.
	TLSPort uint16 `yaml:"tls_port"`
}

// validate returns an error if the DDR record fields are invalid.
func (r *ddrRecord) validate() (err error) {
	if r == nil {
		return errNilConfig
	}

	// TODO(a.garipov): Consider validating that r.DoHPath is a valid RFC 6570
	// URI template.
	if r.HTTPSPort != 0 && r.DoHPath == "" {
		return errors.Error("doh_path: cannot be empty if https_port is set")
	}

	// TODO(a.garipov): Merge with [validateAddrs] and [validateNonNilIPs].
	for i, addr := range r.IPv4Hints {
		if !addr.Is4() {
			return fmt.Errorf("ipv4_hints: at index %d: not an ipv4 addr", i)
		}
	}

	for i, addr := range r.IPv6Hints {
		if !addr.Is6() {
			return fmt.Errorf("ipv6_hints: at index %d: not an ipv6 addr", i)
		}
	}

	return r.validatePorts()
}

// validatePorts returns an error if the DDR record has invalid ports.  r is
// assumed to be otherwise valid.
func (r *ddrRecord) validatePorts() (err error) {
	switch {
	case r.HTTPSPort != 0 && r.HTTPSPort == r.TLSPort:
		return fmt.Errorf("https_port: cannot be same as tls_port, got %d", r.HTTPSPort)
	case r.HTTPSPort == 0 && r.QUICPort == 0 && r.TLSPort == 0:
		return errors.Error("all ports are zero")
	default:
		return nil
	}
}
