package cmd

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
)

// serverGroups are the DNS server groups.  A valid instance of serverGroups has
// no nil items.
type serverGroups []*serverGroup

// toInternal returns the configuration for all server groups in the DNS
// service.  srvGrps and other parts of the configuration must be valid.
func (srvGrps serverGroups) toInternal(
	ctx context.Context,
	messages *dnsmsg.Constructor,
	btdMgr *bindtodevice.Manager,
	tlsMgr tlsconfig.Manager,
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

		var deviceDomains []string
		deviceDomains, err = g.TLS.toInternal(ctx, tlsMgr)
		if err != nil {
			return nil, fmt.Errorf("tls %q: %w", g.Name, err)
		}

		svcSrvGrps[i] = &agd.ServerGroup{
			DDR:             g.DDR.toInternal(messages),
			DeviceDomains:   deviceDomains,
			Name:            agd.ServerGroupName(g.Name),
			FilteringGroup:  fltGrpID,
			ProfilesEnabled: g.ProfilesEnabled,
		}

		svcSrvGrps[i].Servers, err = g.Servers.toInternal(
			btdMgr,
			tlsMgr,
			ratelimitConf,
			dnsConf,
			deviceDomains,
		)
		if err != nil {
			return nil, fmt.Errorf("server group %q: %w", g.Name, err)
		}
	}

	return svcSrvGrps, nil
}

// type check
var _ validator = serverGroups(nil)

// validate implements the [validator] interface for serverGroups.
func (srvGrps serverGroups) validate() (err error) {
	if len(srvGrps) == 0 {
		return errors.ErrEmptyValue
	}

	names := container.NewMapSet[string]()
	for i, g := range srvGrps {
		err = g.validate()
		if err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}

		if names.Has(g.Name) {
			return fmt.Errorf("at index %d: name: %w: %q", i, errors.ErrDuplicated, g.Name)
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

	// ProfilesEnabled, if true, enables recognition of user devices and
	// profiles for this server group.
	ProfilesEnabled bool `yaml:"profiles_enabled"`
}

// type check
var _ validator = (*serverGroup)(nil)

// validate implements the [validator] interface for *serverGroup.
func (g *serverGroup) validate() (err error) {
	switch {
	case g == nil:
		return errors.ErrNoValue
	case g.Name == "":
		return fmt.Errorf("name: %w", errors.ErrEmptyValue)
	case g.FilteringGroup == "":
		return fmt.Errorf("filtering_group: %w", errors.ErrEmptyValue)
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

// collectSessTicketPaths returns the list of unique session ticket file paths
// for all server groups.
func (srvGrps serverGroups) collectSessTicketPaths() (paths []string) {
	set := container.NewSortedSliceSet[string]()
	for _, g := range srvGrps {
		for _, k := range g.TLS.SessionKeys {
			set.Add(k)
		}
	}

	return set.Values()
}
