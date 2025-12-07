package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
)

// toInternal converts a protobuf parental-protection settings structure to an
// internal one.  If x is nil, toInternal returns a disabled configuration.
func (x *ParentalSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	categoryFilter *CategoryFilterSettings,
) (c *filter.ConfigParental, err error) {
	c = &filter.ConfigParental{
		Categories: categoryFilter.toInternal(ctx, errColl, logger),
	}
	if x == nil {
		return c, nil
	}

	c.AdultBlockingEnabled = x.BlockAdult
	c.BlockedServices = blockedSvcsToInternal(ctx, errColl, logger, x.BlockedServices)
	c.Enabled = x.Enabled
	c.SafeSearchGeneralEnabled = x.GeneralSafeSearch
	c.SafeSearchYouTubeEnabled = x.YoutubeSafeSearch

	c.PauseSchedule, err = x.Schedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("pause schedule: %w", err)
	}

	return c, nil
}

// toInternal converts protobuf rate-limiting settings to an internal structure.
// If x is nil, toInternal returns [agd.GlobalRatelimiter].
func (x *RateLimitSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	respSzEst datasize.ByteSize,
) (r agd.Ratelimiter) {
	if x == nil || !x.Enabled {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: cidrRangeToInternal(ctx, errColl, logger, x.ClientCidr),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// toInternal converts protobuf safe-browsing settings to an internal
// safe-browsing configuration.  If x is nil, toInternal returns a disabled
// configuration.
func (x *SafeBrowsingSettings) toInternal() (c *filter.ConfigSafeBrowsing) {
	c = &filter.ConfigSafeBrowsing{}
	if x == nil {
		return c
	}

	c.Enabled = x.Enabled
	c.DangerousDomainsEnabled = x.BlockDangerousDomains
	c.NewlyRegisteredDomainsEnabled = x.BlockNrd

	return c
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].  all arguments must not be
// nil.
func (x *AccessSettings) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
	cons *access.ProfileConstructor,
	standardEnabled bool,
) (a access.Profile) {
	if x == nil || !x.Enabled {
		return access.EmptyProfile{}
	}

	return cons.New(&access.ProfileConfig{
		AllowedNets:          cidrRangeToInternal(ctx, errColl, logger, x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(ctx, errColl, logger, x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
		StandardEnabled:      standardEnabled,
	})
}

// toStandardConfig converts protobuf access settings to an internal structure.
// If x is nil, toStandardConfig returns nil.
func (x *AccessSettings) toStandardConfig(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
) (a *access.StandardBlockerConfig) {
	if x == nil || !x.Enabled {
		logger.WarnContext(ctx, "received disabled standard access settings")

		return nil
	}

	return &access.StandardBlockerConfig{
		AllowedNets:          cidrRangeToInternal(ctx, errColl, logger, x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(ctx, errColl, logger, x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
	}
}

// cidrRangeToInternal is a helper that converts a slice of CidrRange to the
// slice of [netip.Prefix].
func cidrRangeToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	cidrs []*CidrRange,
) (out []netip.Prefix) {
	for i, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.Address)
		if !ok {
			err := fmt.Errorf("bad cidr at index %d: %v", i, c.Address)
			errcoll.Collect(ctx, errColl, logger, "converting cidrs", err)

			continue
		}

		out = append(out, netip.PrefixFrom(addr, int(c.Prefix)))
	}

	return out
}

// asnToInternal is a helper that converts a slice of ASNs to the slice of
// [geoip.ASN].
func asnToInternal(asns []uint32) (out []geoip.ASN) {
	for _, asn := range asns {
		out = append(out, geoip.ASN(asn))
	}

	return out
}

// blockedSvcsToInternal is a helper that converts the blocked service IDs from
// the backend response to AdGuard DNS blocked-service IDs.
func blockedSvcsToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	respSvcs []string,
) (ids []filter.BlockedServiceID) {
	l := len(respSvcs)
	if l == 0 {
		return nil
	}

	ids = make([]filter.BlockedServiceID, 0, l)
	for i, idStr := range respSvcs {
		id, err := filter.NewBlockedServiceID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting blocked services", err)

			continue
		}

		ids = append(ids, id)
	}

	return ids
}

// toInternal converts protobuf custom-domain settings to an internal structure.
// If x is nil, toInternal returns a non-nil config with Enabled set to false.
func (x *CustomDomainSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (c *agd.AccountCustomDomains) {
	if x == nil || !x.Enabled {
		return &agd.AccountCustomDomains{}
	}

	return &agd.AccountCustomDomains{
		Domains: customDomainsToInternal(ctx, errColl, logger, x.Domains),
		Enabled: x.Enabled,
	}
}

// customDomainsToInternal is a helper that converts the settings for each
// custom domain from the backend response to internal structures.  errColl and
// logger must not be nil.
func customDomainsToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	respDomains []*CustomDomain,
) (domains []*agd.CustomDomainConfig) {
	l := len(respDomains)
	if l == 0 {
		return nil
	}

	domains = make([]*agd.CustomDomainConfig, 0, l)
	for i, respDom := range respDomains {
		d, err := respDom.toInternal()
		if err != nil {
			err = fmt.Errorf("custom domains: at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting custom domains", err)

			continue
		}

		domains = append(domains, d)
	}

	return domains
}

// toInternal converts a protobuf custom-domain config to an internal structure.
func (x *CustomDomain) toInternal() (c *agd.CustomDomainConfig, err error) {
	if len(x.Domains) == 0 {
		return nil, fmt.Errorf("domains: %w", errors.ErrEmptyValue)
	}

	c = &agd.CustomDomainConfig{
		// TODO(a.garipov):  Validate domain names?
		Domains: slices.Clone(x.Domains),
	}

	switch s := x.State.(type) {
	case *CustomDomain_Current_:
		var certName agd.CertificateName
		certName, err = agd.NewCertificateName(s.Current.CertName)
		if err != nil {
			return nil, fmt.Errorf("certificate name: %q: %w", s.Current.CertName, err)
		}

		st := &agd.CustomDomainStateCurrent{
			CertName:  certName,
			NotBefore: s.Current.NotBefore.AsTime(),
			NotAfter:  s.Current.NotAfter.AsTime(),
			Enabled:   s.Current.Enabled,
		}

		if st.NotBefore.After(st.NotAfter) || st.NotAfter.Equal(st.NotBefore) {
			return nil, fmt.Errorf(
				"current custom domain: cert %q: NotBefore=%s is not before NotAfter=%s",
				st.CertName,
				st.NotBefore,
				st.NotAfter,
			)
		}

		c.State = st
	case *CustomDomain_Pending_:
		st := &agd.CustomDomainStatePending{
			WellKnownPath: s.Pending.WellKnownPath,
			Expire:        s.Pending.Expire.AsTime(),
		}

		if st.WellKnownPath == "" {
			return nil, fmt.Errorf("well_known_path: %w", errors.ErrEmptyValue)
		}

		c.State = st
	default:
		return nil, fmt.Errorf("bad pb custom domain state %T(%[1]v)", s)
	}

	return c, nil
}

// toInternal converts a protobuf protection-schedule structure to an internal
// one.  If x is nil, toInternal returns nil.
func (x *ScheduleSettings) toInternal() (c *filter.ConfigSchedule, err error) {
	if x == nil {
		return nil, nil
	}

	c = &filter.ConfigSchedule{
		Week: &filter.WeeklySchedule{},
	}

	c.TimeZone, err = agdtime.LoadLocation(x.Tmz)
	if err != nil {
		return nil, fmt.Errorf("loading timezone: %w", err)
	}

	w := x.WeeklyRange
	days := []*DayRange{w.Sun, w.Mon, w.Tue, w.Wed, w.Thu, w.Fri, w.Sat}
	for i, d := range days {
		if d == nil {
			continue
		}

		ivl := &filter.DayInterval{
			Start: uint16(d.Start.AsDuration().Minutes()),
			End:   uint16(d.End.AsDuration().Minutes() + 1),
		}

		err = ivl.Validate()
		if err != nil {
			return nil, fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}

		c.Week[i] = ivl
	}

	return c, nil
}

// toInternal converts a protobuf custom blocking-mode to an internal one.
// Assumes that at least one IP address is specified in the result blocking-mode
// object.
func (pbm *BlockingModeCustomIP) toInternal() (m dnsmsg.BlockingMode, err error) {
	custom := &dnsmsg.BlockingModeCustomIP{}

	// TODO(a.garipov): Only one IPv4 address is supported on protobuf side.
	var ipv4Addr netip.Addr
	err = ipv4Addr.UnmarshalBinary(pbm.Ipv4)
	if err != nil {
		return nil, fmt.Errorf("bad custom ipv4: %w", err)
	} else if ipv4Addr.IsValid() {
		custom.IPv4 = []netip.Addr{ipv4Addr}
	}

	// TODO(a.garipov): Only one IPv6 address is supported on protobuf side.
	var ipv6Addr netip.Addr
	err = ipv6Addr.UnmarshalBinary(pbm.Ipv6)
	if err != nil {
		return nil, fmt.Errorf("bad custom ipv6: %w", err)
	} else if ipv6Addr.IsValid() {
		custom.IPv6 = []netip.Addr{ipv6Addr}
	}

	if len(custom.IPv4)+len(custom.IPv6) == 0 {
		return nil, errors.Error("no valid custom ips found")
	}

	return custom, nil
}

// adultBlockingModeToInternal converts a protobuf adult blocking-mode sum-type
// to an internal one.  If pbm is nil, it returns nil.
func adultBlockingModeToInternal(
	pbm isDNSProfile_AdultBlockingMode,
) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return nil, nil
	case *DNSProfile_AdultBlockingModeCustomIp:
		return pbm.AdultBlockingModeCustomIp.toInternal()
	case *DNSProfile_AdultBlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *DNSProfile_AdultBlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_AdultBlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm)
	}
}

// safeBrowsingBlockingModeToInternal converts a protobuf safe browsing
// blocking-mode sum-type to an internal one.  If pbm is nil, it returns nil.
func safeBrowsingBlockingModeToInternal(
	pbm isDNSProfile_SafeBrowsingBlockingMode,
) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return nil, nil
	case *DNSProfile_SafeBrowsingBlockingModeCustomIp:
		return pbm.SafeBrowsingBlockingModeCustomIp.toInternal()
	case *DNSProfile_SafeBrowsingBlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *DNSProfile_SafeBrowsingBlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_SafeBrowsingBlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm)
	}
}

// blockingModesToInternal converts a protobuf blocking-mode sum-types to
// internal blocking-mode objects.
func blockingModesToInternal(p *DNSProfile) (
	m dnsmsg.BlockingMode,
	adultBlockingMode dnsmsg.BlockingMode,
	safeBrowsingBlockingMode dnsmsg.BlockingMode,
	err error,
) {
	m, err = blockingModeToInternal(p.BlockingMode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("blocking mode: %w", err)
	}

	adultBlockingMode, err = adultBlockingModeToInternal(p.AdultBlockingMode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("adult blocking mode: %w", err)
	}

	safeBrowsingBlockingMode, err = safeBrowsingBlockingModeToInternal(p.SafeBrowsingBlockingMode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("safe browsing blocking mode: %w", err)
	}

	return m, adultBlockingMode, safeBrowsingBlockingMode, nil
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.  If pbm is nil, blockingModeToInternal returns a null-IP
// blocking mode.
//
// TODO(d.kolyshev):  DRY with adultBlockingModeToInternal and
// safeBrowsingBlockingModeToInternal.
func blockingModeToInternal(pbm isDNSProfile_BlockingMode) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_BlockingModeCustomIp:
		return pbm.BlockingModeCustomIp.toInternal()
	case *DNSProfile_BlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *DNSProfile_BlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_BlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm)
	}
}

// rulesToInternal is a helper that converts the filter rules from the backend
// response to AdGuard DNS filtering rules.
func rulesToInternal(
	ctx context.Context,
	respRules []string,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (rules []filter.RuleText) {
	l := len(respRules)
	if l == 0 {
		return nil
	}

	rules = make([]filter.RuleText, 0, l)
	for i, r := range respRules {
		text, err := filter.NewRuleText(r)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting rules", err)

			continue
		}

		rules = append(rules, text)
	}

	return rules
}

// toInternal is a helper that converts the filter lists from the backend
// response to AdGuard DNS rule-list configuration.  If x is nil, toInternal
// returns a disabled configuration.
func (x *RuleListsSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (c *filter.ConfigRuleList) {
	c = &filter.ConfigRuleList{}
	if x == nil {
		return c
	}

	c.Enabled = x.Enabled
	c.IDs = make([]filter.ID, 0, len(x.Ids))

	for i, idStr := range x.Ids {
		id, err := filter.NewID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting filter id", err)

			continue
		}

		c.IDs = append(c.IDs, id)
	}

	return c
}

// toInternal is a helper that converts category filter settings from backend
// response to AdGuard DNS filter categories configuration.  If x is nil,
// toInternal returns a disabled configuration.
func (x *CategoryFilterSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (c *filter.ConfigCategories) {
	c = &filter.ConfigCategories{}
	if x == nil {
		return c
	}

	c.Enabled = x.Enabled
	c.IDs = make([]filter.CategoryID, 0, len(x.Ids))

	for i, idStr := range x.Ids {
		id, err := filter.NewCategoryID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting category id", err)

			continue
		}

		c.IDs = append(c.IDs, id)
	}

	return c
}
