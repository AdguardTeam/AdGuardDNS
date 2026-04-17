package dnspb

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
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/c2h5oh/datasize"
)

// ProfileResult is the result of the conversion of a protobuf profile into an
// internal structure.
type ProfileResult struct {
	// Profile is the profile that has been converted.
	Profile *agd.Profile

	// DeviceChange is the device change that has been sent with this profile,
	// if any.
	DeviceChange *profiledb.StorageDeviceChange

	// Devices are the devices of this profile or the upserted devices if
	// [ProfileResult.DeviceChange] is not nil.
	Devices []*agd.Device

	// NumBadDevice is the number of bad devices in this profile that have been
	// ignored.
	NumBadDevice uint
}

// ToInternal converts device settings from a backend protobuf response to an
// AdGuard DNS profile and its devices or device changes.  l, baseCustomLogger,
// cons, bindSet, and errColl must not be nil.  res is never nil.  If err is not
// nil, res.Profile, res.DeviceChange, and res.Devices are all nil.
//
// TODO(a.garipov):  Consider refactoring conversion by using some kind of
// converter struct.
func (x *DNSProfile) ToInternal(
	ctx context.Context,
	l *slog.Logger,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	respSzEst datasize.ByteSize,
	isFullSync bool,
) (res *ProfileResult, err error) {
	res = &ProfileResult{}
	if x == nil {
		return res, errors.ErrNoValue
	}

	p := &agd.Profile{}
	bm, abm, sbbm, err := blockingModesToInternal(x)
	if err != nil {
		// Do not wrap the error, because it's informative enough as is.
		return res, err
	}

	p.BlockingMode, p.AdultBlockingMode, p.SafeBrowsingBlockingMode = bm, abm, sbbm

	devChg, deviceIDs, devices, numBad := x.devicesToInternal(ctx, l, bindSet, errColl, isFullSync)
	res.NumBadDevice = numBad

	p.ID, err = agd.NewProfileID(x.DnsId)
	if err != nil {
		return res, fmt.Errorf("id: %w", err)
	}

	p.FilterConfig, err = newFilterConfig(ctx, l, x, p.ID, baseCustomLogger, errColl)
	if err != nil {
		return res, fmt.Errorf("filter config: %w", err)
	}

	p.AccountID, err = agd.NewAccountID(x.AccountIdInt)
	if err != nil {
		return res, fmt.Errorf("account id: %w", err)
	}

	x.set(ctx, l, p, cons, deviceIDs, respSzEst, errColl)

	res.Profile = p
	res.DeviceChange = devChg
	res.Devices = devices

	return res, nil
}

// devicesToInternal converts device data from a backend protobuf response to
// AdGuard DNS data about devices or device changes.  l, bindSet, and errColl
// must not be nil.
func (x *DNSProfile) devicesToInternal(
	ctx context.Context,
	l *slog.Logger,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	isFullSync bool,
) (
	devChg *profiledb.StorageDeviceChange,
	deviceIDs []agd.DeviceID,
	devices []*agd.Device,
	numBad uint,
) {
	devChg = &profiledb.StorageDeviceChange{}
	if n := len(x.Devices); n != 0 {
		optslog.Trace2(ctx, l, "got devices", "profile_id", x.DnsId, "len", n)

		devices, deviceIDs, numBad = devicesToInternal(ctx, l, x.Devices, bindSet, errColl)
	} else if n = len(x.DeviceChanges); n != 0 {
		optslog.Trace2(ctx, l, "got device changes", "profile_id", x.DnsId, "len", n)

		devChg.IsPartial = true
		devices, deviceIDs, devChg.DeletedDeviceIDs, numBad = deviceChangesToInternal(
			ctx,
			l,
			x.DeviceChanges,
			bindSet,
			errColl,
		)
	} else {
		// If the sync is full, the absence of devices shows that a profile has
		// no devices, however in a partial sync it shows the absence of changes
		// in the devices.
		devChg.IsPartial = !isFullSync
	}

	return devChg, deviceIDs, devices, numBad
}

// blockingModesToInternal converts a protobuf blocking-mode sum-types to
// internal blocking-mode structures.  p must not be nil.
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
// TODO(d.kolyshev):  DRY with [adultBlockingModeToInternal] and
// [safeBrowsingBlockingModeToInternal].
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

// toInternal converts a protobuf custom blocking-mode to an internal one.
// Assumes that at least one IP address is specified in the result blocking-mode
// struct.
func (x *BlockingModeCustomIP) toInternal() (m dnsmsg.BlockingMode, err error) {
	custom := &dnsmsg.BlockingModeCustomIP{}

	// TODO(a.garipov): Only one IPv4 address is supported on protobuf side.
	var ipv4Addr netip.Addr
	err = ipv4Addr.UnmarshalBinary(x.Ipv4)
	if err != nil {
		return nil, fmt.Errorf("bad custom ipv4: %w", err)
	} else if ipv4Addr.IsValid() {
		custom.IPv4 = []netip.Addr{ipv4Addr}
	}

	// TODO(a.garipov): Only one IPv6 address is supported on protobuf side.
	var ipv6Addr netip.Addr
	err = ipv6Addr.UnmarshalBinary(x.Ipv6)
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

// newFilterConfig creates a new filter configuration from the protobuf profile.
// l, p, baseCustomLogger, and errColl must not be nil.
func newFilterConfig(
	ctx context.Context,
	l *slog.Logger,
	p *DNSProfile,
	id agd.ProfileID,
	baseCustomLogger *slog.Logger,
	errColl errcoll.Interface,
) (c *filter.ConfigClient, err error) {
	parental, err := p.Parental.toInternal(ctx, l, p.CategoryFilter, errColl)
	if err != nil {
		return nil, fmt.Errorf("parental: %w", err)
	}

	customRules := rulesToInternal(ctx, l, p.CustomRules, errColl)
	customEnabled := len(customRules) > 0

	var customFilter filter.Custom
	if customEnabled {
		customFilter = custom.New(&custom.Config{
			Logger: baseCustomLogger.With("client_id", string(id)),
			Rules:  customRules,
		})
	}

	customConf := &filter.ConfigCustomFilter{
		Filter: customFilter,
		// TODO(a.garipov):  Consider adding an explicit flag to the protocol.
		Enabled: customEnabled,
	}

	return &filter.ConfigClient{
		CustomFilter:   customConf,
		CustomRuleList: p.CustomRuleLists.toInternal(ctx, l, errColl),
		Parental:       parental,
		RuleList:       p.RuleLists.toInternal(ctx, l, errColl),
		SafeBrowsing:   p.SafeBrowsing.toInternal(),
	}, nil
}

// toInternal converts a protobuf parental-protection settings structure to an
// internal one.  If x is nil, toInternal returns a disabled partial-protection
// configuration.  l and errColl must not be nil.
func (x *ParentalSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	s *CategoryFilterSettings,
	errColl errcoll.Interface,
) (c *filter.ConfigParental, err error) {
	c = &filter.ConfigParental{
		Categories: s.toInternal(ctx, l, errColl),
	}
	if x == nil {
		return c, nil
	}

	c.AdultBlockingEnabled = x.BlockAdult
	c.BlockedServices = blockedServicesToInternal(ctx, l, x.BlockedServices, errColl)
	c.Enabled = x.Enabled
	c.SafeSearchGeneralEnabled = x.GeneralSafeSearch
	c.SafeSearchYouTubeEnabled = x.YoutubeSafeSearch

	c.PauseSchedule, err = x.Schedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("pause schedule: %w", err)
	}

	return c, nil
}

// rulesToInternal converts the filter rules from the backend response to
// AdGuard DNS filtering rules.  l and errColl must not be nil.
func rulesToInternal(
	ctx context.Context,
	l *slog.Logger,
	respRules []string,
	errColl errcoll.Interface,
) (rules []filter.RuleText) {
	n := len(respRules)
	if n == 0 {
		return nil
	}

	rules = make([]filter.RuleText, 0, n)
	for i, r := range respRules {
		text, err := filter.NewRuleText(r)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, l, "converting rules", err)

			continue
		}

		rules = append(rules, text)
	}

	return rules
}

// toInternal converts the custom filter-list settings from the backend response
// to AdGuard DNS custom rule-list configuration.  If x is nil, toInternal
// returns a disabled configuration.  l and errColl must not be nil.
func (x *CustomRuleListsSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
) (c *filter.ConfigCustomRuleList) {
	c = &filter.ConfigCustomRuleList{}
	if x == nil {
		return c
	}

	c.Enabled, c.IDs = ruleListSettingsData(ctx, l, x, "custom rule-list", errColl)

	return c
}

// ruleListSettings is the common type for [CustomRuleListsSettings] and
// [RuleListsSettings].
type ruleListSettings interface {
	GetEnabled() (ok bool)
	GetIds() (ids []string)
}

// type check
var (
	_ ruleListSettings = (*CustomRuleListsSettings)(nil)
	_ ruleListSettings = (*RuleListsSettings)(nil)
)

// ruleListSettingsData converts the data from the given rule-list settings to
// AdGuard DNS entities.  Errors are reported to the error collector and logged.
// kind is used for error reporting and logging.  l, s, and errColl must not be
// nil.
func ruleListSettingsData(
	ctx context.Context,
	l *slog.Logger,
	s ruleListSettings,
	kind string,
	errColl errcoll.Interface,
) (enabled bool, ids []filter.ID) {
	enabled = s.GetEnabled()
	idStrs := s.GetIds()
	n := len(idStrs)
	if n == 0 {
		return enabled, nil
	}

	ids = make([]filter.ID, 0, n)

	for i, idStr := range idStrs {
		id, err := filter.NewID(idStr)
		if err != nil {
			err = fmt.Errorf("converting %s filter ids: at index %d: %w", kind, i, err)
			errcoll.Collect(ctx, errColl, l, "converting rule-list settings", err)

			continue
		}

		ids = append(ids, id)
	}

	return enabled, ids
}

// toInternal converts the filter lists from the backend response to AdGuard DNS
// rule-list configuration.  If x is nil, toInternal returns a disabled
// configuration.  l and errColl must not be nil.
func (x *RuleListsSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
) (c *filter.ConfigRuleList) {
	c = &filter.ConfigRuleList{}
	if x == nil {
		return c
	}

	c.Enabled, c.IDs = ruleListSettingsData(ctx, l, x, "rule-list", errColl)

	return c
}

// toInternal converts protobuf safe-browsing settings to an internal
// safe-browsing configuration.  If x is nil, toInternal returns a disabled
// configuration.
func (x *SafeBrowsingSettings) toInternal() (c *filter.ConfigSafeBrowsing) {
	c = &filter.ConfigSafeBrowsing{
		Typosquatting: &filter.ConfigTyposquatting{},
	}
	if x == nil {
		return c
	}

	c.Typosquatting = x.Typosquatting.toInternal()
	c.Enabled = x.Enabled
	c.DangerousDomainsEnabled = x.BlockDangerousDomains
	c.NewlyRegisteredDomainsEnabled = x.BlockNrd

	return c
}

// toInternal converts protobuf typosquatting settings to an internal
// typosquatting configuration.  If x is nil, toInternal returns a disabled
// configuration.
func (x *TyposquattingFilterSettings) toInternal() (c *filter.ConfigTyposquatting) {
	return &filter.ConfigTyposquatting{
		Enabled: x.GetEnabled(),
	}
}

// toInternal converts category filter settings from backend response to AdGuard
// DNS filter categories configuration.  If x is nil, toInternal returns a
// disabled configuration.  l and errColl must not be nil.
func (x *CategoryFilterSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
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
			errcoll.Collect(ctx, errColl, l, "converting category id", err)

			continue
		}

		c.IDs = append(c.IDs, id)
	}

	return c
}

// blockedServicesToInternal is a helper that converts the blocked service IDs
// from the backend response to AdGuard DNS blocked-service IDs.  l and errColl
// must not be nil.
func blockedServicesToInternal(
	ctx context.Context,
	l *slog.Logger,
	pbIDs []string,
	errColl errcoll.Interface,
) (ids []filter.BlockedServiceID) {
	n := len(pbIDs)
	if n == 0 {
		return nil
	}

	ids = make([]filter.BlockedServiceID, 0, n)
	for i, idStr := range pbIDs {
		id, err := filter.NewBlockedServiceID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, l, "converting blocked services", err)

			continue
		}

		ids = append(ids, id)
	}

	return ids
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

// toInternal converts protobuf custom-domain settings to an internal structure.
// If x is nil, toInternal returns a non-nil config with Enabled set to false.
// All arguments must not be nil.
func (x *CustomDomainSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
) (c *agd.AccountCustomDomains) {
	if !x.GetEnabled() {
		return &agd.AccountCustomDomains{}
	}

	return &agd.AccountCustomDomains{
		Domains: customDomainsToInternal(ctx, l, x.Domains, errColl),
		Enabled: x.Enabled,
	}
}

// customDomainsToInternal converts the settings for each custom domain from the
// backend response to internal structures.  l, errColl, and all elements of
// pbDomains must not be nil.
func customDomainsToInternal(
	ctx context.Context,
	l *slog.Logger,
	pbDomains []*CustomDomain,
	errColl errcoll.Interface,
) (domains []*agd.CustomDomainConfig) {
	n := len(pbDomains)
	if n == 0 {
		return nil
	}

	domains = make([]*agd.CustomDomainConfig, 0, n)
	for i, respDom := range pbDomains {
		d, err := respDom.toInternal()
		if err != nil {
			err = fmt.Errorf("custom domains: at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, l, "converting custom domains", err)

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

// toInternal converts protobuf rate-limiting settings to an internal structure.
// If x is nil, toInternal returns [agd.GlobalRatelimiter].  l and errColl must
// not be nil.
func (x *RateLimitSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
	respSzEst datasize.ByteSize,
) (r agd.Ratelimiter) {
	if !x.GetEnabled() {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: CIDRRangeToInternal(ctx, l, x.ClientCidr, errColl),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// set assigns p's fields that can be assigned relatively easily.  l, p, cons,
// and errColl must not be nil.
func (x *DNSProfile) set(
	ctx context.Context,
	l *slog.Logger,
	p *agd.Profile,
	cons *access.ProfileConstructor,
	deviceIDs []agd.DeviceID,
	respSzEst datasize.ByteSize,
	errColl errcoll.Interface,
) {
	p.CustomDomains = x.CustomDomain.toInternal(ctx, l, errColl)
	p.DeviceIDs = container.NewMapSet(deviceIDs...)
	p.Access = x.Access.toInternal(ctx, l, errColl, cons, x.StandardAccessSettingsEnabled)
	p.Ratelimiter = x.RateLimit.toInternal(ctx, l, errColl, respSzEst)
	p.FilteredResponseTTL = x.GetFilteredResponseTtl().AsDuration()
	p.AutoDevicesEnabled = x.AutoDevicesEnabled
	p.BlockChromePrefetch = x.BlockChromePrefetch
	p.BlockFirefoxCanary = x.BlockFirefoxCanary
	p.BlockPrivateRelay = x.BlockPrivateRelay
	p.Deleted = x.Deleted
	p.FilteringEnabled = x.FilteringEnabled
	p.IPLogEnabled = x.IpLogEnabled
	p.QueryLogEnabled = x.QueryLogEnabled
	p.QueryLogStream = x.QueryLogStream
}
