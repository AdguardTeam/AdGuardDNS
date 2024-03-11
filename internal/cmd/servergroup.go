package cmd

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
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
			BlockPageRedirect: g.BlockPageRedirect.toInternal(),
			DDR:               g.DDR.toInternal(messages),
			TLS:               tlsConf,
			Name:              agd.ServerGroupName(g.Name),
			FilteringGroup:    fltGrpID,
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

	names := stringutil.NewSet()
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
	// BlockPageRedirect is the configuration for the server group's block page.
	BlockPageRedirect *serverGroupBlockPageConfig `yaml:"block_page_redirect"`

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

	err = g.BlockPageRedirect.validate()
	if err != nil {
		return fmt.Errorf("block_page_redirect: %w", err)
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

// serverGroupBlockPageConfig is the configuration for a [serverGroup]'s block
// page.  See [agd.BlockPageRedirect] and the related types for more
// documentation and contracts.
type serverGroupBlockPageConfig struct {
	// Apply defines request parameters based on which the block page is always
	// shown.
	Apply *serverGroupBlockPageApplyConfig `yaml:"apply"`

	// Skip defines request parameters based on which the block page is never
	// shown, regardless of the probability.
	Skip *serverGroupBlockPageSkipConfig `yaml:"skip"`

	// IPv4 are the IPv4 records of the block page, used to respond to A
	// queries.
	IPv4 []*serverGroupBlockPageRecord `yaml:"ipv4"`

	// IPv6 are the IPv6 records of the block page, used to respond to AAAA
	// queries.
	IPv6 []*serverGroupBlockPageRecord `yaml:"ipv6"`

	// Probability defines the probability of responding with the block page IPs
	// based on remote address.
	Probability float64 `yaml:"probability"`

	// Enabled defines whether the block-page feature is enabled.
	Enabled bool `yaml:"enabled"`
}

// toInternal returns the block-page redirect configuration for a server group.
// c is assumed to be valid.
func (c *serverGroupBlockPageConfig) toInternal() (conf *agd.BlockPageRedirect) {
	if !c.Enabled {
		return &agd.BlockPageRedirect{}
	}

	var ipv4 []netip.Addr
	for _, r := range c.IPv4 {
		ipv4 = append(ipv4, r.Address)
	}

	var ipv6 []netip.Addr
	for _, r := range c.IPv6 {
		ipv6 = append(ipv6, r.Address)
	}

	return &agd.BlockPageRedirect{
		Apply:       c.Apply.toInternal(),
		Skip:        c.Skip.toInternal(),
		IPv4:        ipv4,
		IPv6:        ipv6,
		Probability: agd.MustNewProbability(c.Probability),
		Enabled:     c.Enabled,
	}
}

// validate returns an error if the block-page redirect configuration is
// invalid.
func (c *serverGroupBlockPageConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case !c.Enabled:
		return nil
	case len(c.IPv4) == 0 && len(c.IPv6) == 0:
		return errors.Error("ipv4, ipv6, or both must be set")
	}

	_, err = agd.NewProbability(c.Probability)
	if err != nil {
		return fmt.Errorf("probability: %w", err)
	}

	err = c.validateAddrs()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = c.Apply.validate()
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	err = c.Skip.validate()
	if err != nil {
		return fmt.Errorf("skip: %w", err)
	}

	return nil
}

// validateAddrs returns an error if the block-page redirect if the IP addresses
// in the block-page redirect configuration are invalid.
func (c *serverGroupBlockPageConfig) validateAddrs() (err error) {
	for i, r := range c.IPv4 {
		err = r.validate()
		if err != nil {
			return fmt.Errorf("ipv4: at index %d: address: %w", i, err)
		} else if !r.Address.Is4() {
			return fmt.Errorf("ipv4: at index %d: address: not ipv4: %v", i, r.Address)
		}
	}

	for i, r := range c.IPv6 {
		err = r.validate()
		if err != nil {
			return fmt.Errorf("ipv6: at index %d: %w", i, err)
		} else if !r.Address.Is6() {
			return fmt.Errorf("ipv6: at index %d: address: not ipv6: %v", i, r.Address)
		}
	}

	return nil
}

// serverGroupBlockPageRecord is a structure for defining answer records in
// [serverGroupBlockPageConfig].
type serverGroupBlockPageRecord struct {
	Address netip.Addr `yaml:"address"`
}

// validate returns an error if the record configuration is invalid.
func (c *serverGroupBlockPageRecord) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case !c.Address.IsValid():
		return errors.Error("invalid addr")
	default:
		return nil
	}
}

// serverGroupBlockPageApplyConfig defines the conditions for applying the
// block-page logic for a particular request.
type serverGroupBlockPageApplyConfig struct {
	// Client are the parameters for clients for which block page is always
	// enabled.
	Client []*serverGroupBlockPageClientConfig `yaml:"client"`
}

// toInternal returns the block-page redirect applying configuration for a
// server group.  c is assumed to be valid.
func (c *serverGroupBlockPageApplyConfig) toInternal() (conf *agd.BlockPageRedirectApply) {
	var subnets []netip.Prefix
	for _, cli := range c.Client {
		subnets = append(subnets, cli.Address.Prefix)
	}

	return &agd.BlockPageRedirectApply{
		ClientSubnets: subnets,
	}
}

// validate returns an error if the block-page redirect applying configuration
// is invalid.
func (c *serverGroupBlockPageApplyConfig) validate() (err error) {
	if c == nil {
		return errNilConfig
	}

	for i, cli := range c.Client {
		err = cli.validate()
		if err != nil {
			return fmt.Errorf("client: at index %d: %w", i, err)
		}
	}

	return nil
}

// serverGroupBlockPageClientConfig is a common structure for defining clients
// in [serverGroupBlockPageSkipConfig] and [serverGroupBlockPageApplyConfig].
type serverGroupBlockPageClientConfig struct {
	Address netutil.Prefix `yaml:"address"`
}

// validate returns an error if the client configuration is invalid.
func (c *serverGroupBlockPageClientConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case !c.Address.IsValid():
		return errors.Error("invalid addr")
	default:
		return nil
	}
}

// serverGroupBlockPageSkipConfig defines the conditions for skipping the block
// page logic for a particular request.
type serverGroupBlockPageSkipConfig struct {
	// Client are the parameters for clients for which block page is always
	// disabled.
	Client []*serverGroupBlockPageClientConfig `yaml:"client"`

	// QuestionDomains are the parameters for request questions for which block
	// page is always disabled.
	Question []*serverGroupBlockPageQuestionConfig `yaml:"question"`
}

// toInternal returns the block-page redirect skipping configuration for a
// server group.  c is assumed to be valid.
func (c *serverGroupBlockPageSkipConfig) toInternal() (conf *agd.BlockPageRedirectSkip) {
	var subnets []netip.Prefix
	for _, cli := range c.Client {
		subnets = append(subnets, cli.Address.Prefix)
	}

	var domains []string
	for _, q := range c.Question {
		domains = append(domains, q.Domain)
	}

	return &agd.BlockPageRedirectSkip{
		ClientSubnets:   subnets,
		QuestionDomains: domains,
	}
}

// validate returns an error if the block-page redirect skipping configuration
// is invalid.
func (c *serverGroupBlockPageSkipConfig) validate() (err error) {
	if c == nil {
		return errNilConfig
	}

	for i, cli := range c.Client {
		err = cli.validate()
		if err != nil {
			return fmt.Errorf("client: at index %d: %w", i, err)
		}
	}

	for i, q := range c.Question {
		switch {
		case q == nil:
			return fmt.Errorf("question: at index %d: %w", i, errNilConfig)
		case q.Domain == "":
			return fmt.Errorf("question: at index %d: %w", i, errors.Error("empty domain"))
		}
	}

	return nil
}

// serverGroupBlockPageQuestionConfig is a structure for defining question
// domains in [serverGroupBlockPageRedirectSkip].
type serverGroupBlockPageQuestionConfig struct {
	Domain string `yaml:"domain"`
}
