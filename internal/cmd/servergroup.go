package cmd

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
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
) (svcSrvGrps []*dnssvc.ServerGroupConfig, err error) {
	svcSrvGrps = make([]*dnssvc.ServerGroupConfig, 0, len(srvGrps))
	for _, g := range srvGrps {
		// TODO(e.burkov):  Validate in [serverGroupsValidator.Validate].
		fltGrpID := agd.FilteringGroupID(g.FilteringGroup)
		_, ok := fltGrps[fltGrpID]
		if !ok {
			return nil, fmt.Errorf("server group %q: unknown filtering group %q", g.Name, fltGrpID)
		}

		certNames, deviceDomains := g.TLS.toInternal()

		groupConfig := &dnssvc.ServerGroupConfig{
			DDR:             g.DDR.toInternal(messages),
			DeviceDomains:   deviceDomains,
			Name:            agd.ServerGroupName(g.Name),
			FilteringGroup:  fltGrpID,
			ProfilesEnabled: g.ProfilesEnabled,
		}

		groupConfig.Servers, err = g.Servers.toInternal(
			ctx,
			btdMgr,
			tlsMgr,
			ratelimitConf,
			dnsConf,
			certNames,
			deviceDomains,
		)
		if err != nil {
			return nil, fmt.Errorf("server group %q: %w", g.Name, err)
		}

		svcSrvGrps = append(svcSrvGrps, groupConfig)
	}

	return svcSrvGrps, nil
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
	TLS *serverGroupTLSConfig `yaml:"tls"`

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
var _ tlsValidator = (*serverGroup)(nil)

// validate implements the [validatorWithTLS] interface for *serverGroup.
func (g *serverGroup) validate(tlsConf *tlsConfig, ts *tlsState) (err error) {
	if g == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmpty("name", g.Name),
		validate.NotEmpty("filtering_group", g.FilteringGroup),
	}

	errs = validate.Append(errs, "ddr", g.DDR)

	needsTLS, err := g.Servers.validateWithTLS()
	if err != nil {
		errs = append(errs, fmt.Errorf("servers: %w", err))
	}

	err = g.TLS.validateIfNecessary(needsTLS, tlsConf, *ts)
	if err != nil {
		errs = append(errs, fmt.Errorf("tls: %w", err))
	}

	return errors.Join(errs...)
}

// collectSessTicketPaths returns the list of unique session ticket file paths
// for all server groups.
func (srvGrps serverGroups) collectSessTicketPaths() (paths []string) {
	set := container.NewSortedSliceSet[string]()
	for _, g := range srvGrps {
		grpTLS := g.TLS
		if grpTLS == nil {
			continue
		}

		for _, k := range grpTLS.SessionKeys {
			set.Add(k)
		}
	}

	return set.Values()
}

// type check
var _ tlsValidator = (serverGroups)(nil)

// validate implements the [tlsValidator] interface for serverGroups.
func (srvGrps serverGroups) validate(tlsConf *tlsConfig, ts *tlsState) (err error) {
	if len(srvGrps) == 0 {
		return errors.ErrEmptyValue
	}

	var errs []error
	names := container.NewMapSet[string]()
	for i, g := range srvGrps {
		err = g.validate(tlsConf, ts)
		if err != nil {
			errs = append(errs, fmt.Errorf("at index %d: %w", i, err))

			continue
		}

		if names.Has(g.Name) {
			errs = append(errs, fmt.Errorf("at index %d: %w: %q", i, errors.ErrDuplicated, g.Name))

			continue
		}

		names.Add(g.Name)
	}

	return errors.Join(errs...)
}
