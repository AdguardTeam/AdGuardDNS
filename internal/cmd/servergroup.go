package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
)

// serverGroups are the DNS server groups.  A valid instance of serverGroups has
// no nil items.
type serverGroups []*serverGroup

// toInternal returns the configuration for all server groups in the DNS
// service.  srvGrps and other parts of the configuration are assumed to be
// valid.
func (srvGrps serverGroups) toInternal(
	messages *dnsmsg.Constructor,
	btdMgr *bindtodevice.Manager,
	fltGrps map[agd.FilteringGroupID]*agd.FilteringGroup,
	ratelimitConf *rateLimitConfig,
	dnsConf *dnsConfig,
) (svcSrvGrps []*agd.ServerGroup, err error) {
	svcSrvGrps = make([]*agd.ServerGroup, len(srvGrps))
	for i, g := range srvGrps {
		fltGrpID := agd.FilteringGroupID(g.FilteringGroup)
		_, ok := fltGrps[fltGrpID]
		if !ok {
			return nil, fmt.Errorf("server group %q: unknown filtering group %q", g.Name, fltGrpID)
		}

		var tlsConf *agd.TLS
		tlsConf, err = g.TLS.toInternal()
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}

		svcSrvGrps[i] = &agd.ServerGroup{
			DDR:            g.DDR.toInternal(messages),
			TLS:            tlsConf,
			Name:           agd.ServerGroupName(g.Name),
			FilteringGroup: fltGrpID,
		}

		svcSrvGrps[i].Servers, err = g.Servers.toInternal(tlsConf, btdMgr, ratelimitConf, dnsConf)
		if err != nil {
			return nil, fmt.Errorf("server group %q: %w", g.Name, err)
		}
	}

	return svcSrvGrps, nil
}

// validate returns an error if these server groups are invalid.
func (srvGrps serverGroups) validate() (err error) {
	if len(srvGrps) == 0 {
		return errors.Error("no server groups")
	}

	names := container.NewMapSet[string]()
	for i, g := range srvGrps {
		err = g.validate()
		if err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}

		if names.Has(g.Name) {
			return fmt.Errorf("at index %d: duplicate name %q", i, g.Name)
		}

		names.Add(g.Name)
	}

	return nil
}

// serverGroup defines a group of DNS servers all of which use the same
// filtering settings.
//
// TODO(a.garipov):  Think about more consistent naming, since this object is a
// configuration, but it also stores other configurations.
type serverGroup struct {
	// DDR is the Discovery Of Designated Resolvers (DDR) configuration for this
	// server group.
	DDR *ddrConfig `yaml:"ddr"`

	// TLS are the TLS settings for this server, if any.
	TLS *tlsConfig `yaml:"tls"`

	// Name is the unique name of the server group.
	Name string `yaml:"name"`

	// FilteringGroup is the name of the filtering group.
	FilteringGroup string `yaml:"filtering_group"`

	// Servers are the settings for servers.
	Servers servers `yaml:"servers"`
}

// validate returns an error if the configuration is invalid.
func (g *serverGroup) validate() (err error) {
	switch {
	case g == nil:
		return errNilConfig
	case g.Name == "":
		return errors.Error("no name")
	case g.FilteringGroup == "":
		return errors.Error("no filtering_group")
	}

	err = g.DDR.validate()
	if err != nil {
		return fmt.Errorf("ddr: %w", err)
	}

	needsTLS, err := g.Servers.validate()
	if err != nil {
		return fmt.Errorf("servers: %w", err)
	}

	err = g.TLS.validate(needsTLS)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}

	return nil
}
