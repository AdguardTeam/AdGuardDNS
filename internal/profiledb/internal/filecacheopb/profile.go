package filecacheopb

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// profilesToInternal converts protobuf profile structures into internal ones.
// baseCustomLogger and cons must not be nil.
//
// TODO(f.setrakov): Do not rely on builders and reuse entities.
func profilesToInternal(
	pbProfiles []*fcpb.Profile,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (profiles []*agd.Profile, err error) {
	profiles = make([]*agd.Profile, 0, len(pbProfiles))
	for i, pbProf := range pbProfiles {
		var prof *agd.Profile
		prof, err = profileToInternal(pbProf, baseCustomLogger, cons, respSzEst)
		if err != nil {
			return nil, fmt.Errorf("profile at index %d: %w", i, err)
		}

		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// profileToInternal converts a protobuf profile structure to an internal one.
// baseCustomLogger, cons and pbProfile must not be nil.
func profileToInternal(
	pbProfile *fcpb.Profile,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (prof *agd.Profile, err error) {
	bmAdult, bmSafeBrowsing, bm, err := blockingModesToInternal(pbProfile)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	customDomains, err := customDomainsToInternal(pbProfile)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	fltConf, err := configClientToInternal(pbProfile, baseCustomLogger)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &agd.Profile{
		CustomDomains: customDomains,
		FilterConfig:  fltConf,

		Access:                   accessToInternal(pbProfile.GetAccess(), cons),
		AdultBlockingMode:        bmAdult,
		BlockingMode:             bm,
		SafeBrowsingBlockingMode: bmSafeBrowsing,
		Ratelimiter:              rateLimiterToInternal(pbProfile.GetRatelimiter(), respSzEst),

		AccountID: agd.AccountID(pbProfile.GetAccountId()),
		ID:        agd.ProfileID(pbProfile.GetProfileId()),

		// Consider device IDs to have been prevalidated.
		DeviceIDs: container.NewMapSet(
			agdprotobuf.UnsafelyConvertStrSlice[string, agd.DeviceID](pbProfile.GetDeviceIds())...,
		),

		// Consider rule-list IDs to have been prevalidated.
		FilteredResponseTTL: pbProfile.GetFilteredResponseTtl().AsDuration(),

		AutoDevicesEnabled:  pbProfile.GetAutoDevicesEnabled(),
		BlockChromePrefetch: pbProfile.GetBlockChromePrefetch(),
		BlockFirefoxCanary:  pbProfile.GetBlockFirefoxCanary(),
		BlockPrivateRelay:   pbProfile.GetBlockPrivateRelay(),
		Deleted:             pbProfile.GetDeleted(),
		FilteringEnabled:    pbProfile.GetFilteringEnabled(),
		IPLogEnabled:        pbProfile.GetIpLogEnabled(),
		QueryLogEnabled:     pbProfile.GetQueryLogEnabled(),
	}, nil
}

// customDomainsToInternal converts profile's protobuf custom domains structures
// into internal ones.  pbProfile must not be nil.
func customDomainsToInternal(
	pbProfile *fcpb.Profile,
) (customDomains *agd.AccountCustomDomains, err error) {
	pbConfs := pbProfile.GetCustomDomains().GetDomains()
	customDomainConfs, err := customDomainConfsToInternal(pbConfs)
	if err != nil {
		return nil, fmt.Errorf("custom domain configs: %w", err)
	}

	customDomains = &agd.AccountCustomDomains{
		Domains: customDomainConfs,
		Enabled: pbProfile.GetCustomDomains().GetEnabled(),
	}

	return customDomains, nil
}

// configClientToInternal converts profile's protobuf config client structures
// into internal ones.  pbProfile and baseCustomLogger must not be nil.
func configClientToInternal(
	pbProfile *fcpb.Profile,
	baseCustomLogger *slog.Logger,
) (fltConf *filter.ConfigClient, err error) {
	pbFltConf := pbProfile.GetFilterConfig()
	pbFltConfSched := pbFltConf.GetParental().GetPauseSchedule()
	schedule, err := filterConfigScheduleToInternal(pbFltConfSched)
	if err != nil {
		return nil, fmt.Errorf("pause schedule: %w", err)
	}

	// Consider the rules to have been prevalidated.
	pbRules := pbFltConf.GetCustom().GetRules()
	rules := agdprotobuf.UnsafelyConvertStrSlice[string, filter.RuleText](pbRules)

	var flt filter.Custom
	if len(rules) > 0 {
		flt = custom.New(&custom.Config{
			Logger: baseCustomLogger.With("client_id", pbProfile.GetProfileId()),
			Rules:  rules,
		})
	}

	ruleListIDs := pbFltConf.GetRuleList().GetIds()
	safeBrowsing := pbFltConf.GetSafeBrowsing()
	fltConf = &filter.ConfigClient{
		Custom: &filter.ConfigCustom{
			Filter:  flt,
			Enabled: pbFltConf.GetCustom().GetEnabled(),
		},
		Parental: configParentalToInternal(pbFltConf, schedule),
		RuleList: &filter.ConfigRuleList{
			// Consider rule-list IDs to have been prevalidated.
			IDs:     agdprotobuf.UnsafelyConvertStrSlice[string, filter.ID](ruleListIDs),
			Enabled: pbFltConf.GetRuleList().GetEnabled(),
		},
		SafeBrowsing: &filter.ConfigSafeBrowsing{
			Enabled:                       safeBrowsing.GetEnabled(),
			DangerousDomainsEnabled:       safeBrowsing.GetDangerousDomainsEnabled(),
			NewlyRegisteredDomainsEnabled: safeBrowsing.GetNewlyRegisteredDomainsEnabled(),
		},
	}

	return fltConf, nil
}

// categoryFilterToInternal converts filter config's protobuf category filter
// structure to internal one.  If categories filter is not specified, returns a
// disabled config.
func categoryFilterToInternal(pbFltConf *fcpb.FilterConfig) (c *filter.ConfigCategories) {
	pbCatFlt := pbFltConf.GetParental().GetCategoryFilter()
	if pbCatFlt == nil {
		// TODO(d.kolyshev):  Remove after moving deprecated profile categories
		// in [internal/profiledb/internal.FileCacheVersion] 19.
		//
		//lint:ignore SA1019 Use deprecated field for compatibility.
		pbCatFlt = pbFltConf.GetCategoryFilter()
		if pbCatFlt == nil {
			return &filter.ConfigCategories{}
		}
	}

	// Consider the categories to have been prevalidated.
	ids := agdprotobuf.UnsafelyConvertStrSlice[string, filter.CategoryID](pbCatFlt.GetIds())
	return &filter.ConfigCategories{
		IDs:     ids,
		Enabled: pbCatFlt.GetEnabled(),
	}
}

// configParentalToInternal converts filter config's protobuf parental config
// structures to internal ones.  pbFltConf must not be nil.
func configParentalToInternal(
	pbFltConf *fcpb.FilterConfig,
	schedule *filter.ConfigSchedule,
) (c *filter.ConfigParental) {
	parental := pbFltConf.GetParental()

	return &filter.ConfigParental{
		Categories:    categoryFilterToInternal(pbFltConf),
		PauseSchedule: schedule,
		// Consider blocked-service IDs to have been prevalidated.
		BlockedServices: agdprotobuf.UnsafelyConvertStrSlice[string, filter.BlockedServiceID](
			parental.GetBlockedServices(),
		),
		Enabled:                  parental.GetEnabled(),
		AdultBlockingEnabled:     parental.GetAdultBlockingEnabled(),
		SafeSearchGeneralEnabled: parental.GetSafeSearchGeneralEnabled(),
		SafeSearchYouTubeEnabled: parental.GetSafeSearchYoutubeEnabled(),
	}
}

// blockingModesToInternal converts profile's protobuf blocking mode structures
// into internal ones.
func blockingModesToInternal(pbProfile *fcpb.Profile) (
	bmAdult dnsmsg.BlockingMode,
	bmSafeBrowsing dnsmsg.BlockingMode,
	bm dnsmsg.BlockingMode,
	err error,
) {
	bmAdult, err = adultBlockingModeToInternal(pbProfile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("adult blocking mode: %w", err)
	}

	bmSafeBrowsing, err = safeBrowsingBlockingModeToInternal(pbProfile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("safe browsing blocking mode: %w", err)
	}

	bm, err = blockingModeToInternal(pbProfile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("blocking mode: %w", err)
	}

	return bmAdult, bmSafeBrowsing, bm, nil
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
// TODO(d.kolyshev):  DRY with adultBlockingModeToInternal and
// safeBrowsingBlockingModeToInternal.
func blockingModeToInternal(pbProfile *fcpb.Profile) (m dnsmsg.BlockingMode, err error) {
	if !pbProfile.HasBlockingMode() {
		return nil, nil
	}

	customIP := pbProfile.GetBlockingModeCustomIp()

	switch {
	case customIP != nil:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv4())
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv6())
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case pbProfile.GetBlockingModeNxdomain() != nil:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case pbProfile.GetBlockingModeNullIp() != nil:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case pbProfile.GetBlockingModeRefused() != nil:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		return nil, fmt.Errorf("bad pb blocking mode")
	}
}

// adultBlockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
func adultBlockingModeToInternal(pbProfile *fcpb.Profile) (m dnsmsg.BlockingMode, err error) {
	if !pbProfile.HasAdultBlockingMode() {
		return nil, nil
	}

	customIP := pbProfile.GetAdultBlockingModeCustomIp()

	switch {
	case customIP != nil:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv4())
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv6())
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case pbProfile.GetAdultBlockingModeNxdomain() != nil:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case pbProfile.GetAdultBlockingModeNullIp() != nil:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case pbProfile.GetAdultBlockingModeRefused() != nil:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		return nil, fmt.Errorf("bad pb adult blocking mode")
	}
}

// safeBrowsingBlockingModeToInternal converts a protobuf blocking-mode sum-type
// to an internal one.
func safeBrowsingBlockingModeToInternal(
	pbProfile *fcpb.Profile,
) (m dnsmsg.BlockingMode, err error) {
	if !pbProfile.HasSafeBrowsingBlockingMode() {
		return nil, nil
	}

	customIP := pbProfile.GetSafeBrowsingBlockingModeCustomIp()

	switch {
	case customIP != nil:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv4())
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(customIP.GetIpv6())
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case pbProfile.GetSafeBrowsingBlockingModeNxdomain() != nil:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case pbProfile.GetSafeBrowsingBlockingModeNullIp() != nil:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case pbProfile.GetSafeBrowsingBlockingModeRefused() != nil:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		return nil, fmt.Errorf("bad pb safe browsing blocking mode")
	}
}

// filterConfigScheduleToInternal converts a protobuf protection-schedule
// structure to an internal one.
func filterConfigScheduleToInternal(
	pbSchedule *fcpb.FilterConfig_Schedule,
) (c *filter.ConfigSchedule, err error) {
	if pbSchedule == nil {
		return nil, nil
	}

	loc, err := agdtime.LoadLocation(pbSchedule.GetTimeZone())
	if err != nil {
		return nil, fmt.Errorf("time zone: %w", err)
	}

	week := pbSchedule.GetWeek()
	return &filter.ConfigSchedule{
		// Consider the lengths to be prevalidated.
		Week: &filter.WeeklySchedule{
			time.Monday:    dayIntervalToInternal(week.GetMon()),
			time.Tuesday:   dayIntervalToInternal(week.GetTue()),
			time.Wednesday: dayIntervalToInternal(week.GetWed()),
			time.Thursday:  dayIntervalToInternal(week.GetThu()),
			time.Friday:    dayIntervalToInternal(week.GetFri()),
			time.Saturday:  dayIntervalToInternal(week.GetSat()),
			time.Sunday:    dayIntervalToInternal(week.GetSun()),
		},
		TimeZone: loc,
	}, nil
}

// dayIntervalToInternal converts a protobuf day interval to an internal one.
func dayIntervalToInternal(pbInterval *fcpb.DayInterval) (i *filter.DayInterval) {
	if pbInterval == nil {
		return nil
	}

	return &filter.DayInterval{
		// #nosec G115 -- The values put in these are always from uint16s.
		Start: uint16(pbInterval.GetStart()),
		// #nosec G115 -- The values put in these are always from uint16s.
		End: uint16(pbInterval.GetEnd()),
	}
}

// customDomainConfsToInternal converts protobuf custom-domain configurations to
// internal ones.
func customDomainConfsToInternal(
	pbConfs []*fcpb.CustomDomainConfig,
) (confs []*agd.CustomDomainConfig, err error) {
	l := len(pbConfs)
	if l == 0 {
		return nil, nil
	}

	confs = make([]*agd.CustomDomainConfig, 0, l)
	for i, pbConf := range pbConfs {
		var c *agd.CustomDomainConfig
		c, err = customDomainConfigToInternal(pbConf)
		if err != nil {
			return nil, fmt.Errorf("at index %d: %w", i, err)
		}

		confs = append(confs, c)
	}

	return confs, nil
}

// customDomainConfigToInternal converts a protobuf custom-domain config to an
// internal one.  pbCustomDomainConf must not be nil.
func customDomainConfigToInternal(
	pbCustomDomainConf *fcpb.CustomDomainConfig,
) (c *agd.CustomDomainConfig, err error) {
	var state agd.CustomDomainState

	if current := pbCustomDomainConf.GetStateCurrent(); current != nil {
		state = &agd.CustomDomainStateCurrent{
			NotBefore: current.GetNotBefore().AsTime(),
			NotAfter:  current.GetNotAfter().AsTime(),
			// Consider certificate names to have been prevalidated.
			CertName: agd.CertificateName(current.GetCertName()),
			Enabled:  current.GetEnabled(),
		}
	} else if pending := pbCustomDomainConf.GetStatePending(); pending != nil {
		state = &agd.CustomDomainStatePending{
			Expire:        pending.GetExpire().AsTime(),
			WellKnownPath: pending.GetWellKnownPath(),
		}
	} else {
		return nil, fmt.Errorf("pb unknown domain state: %w", errors.ErrBadEnumValue)
	}

	return &agd.CustomDomainConfig{
		State:   state,
		Domains: slices.Clone(pbCustomDomainConf.GetDomains()),
	}, nil
}

// rateLimiterToInternal converts a protobuf rate-limiting settings structure to
// an internal one.
func rateLimiterToInternal(
	pbRateLimiter *fcpb.Ratelimiter,
	respSzEst datasize.ByteSize,
) (r agd.Ratelimiter) {
	if !pbRateLimiter.GetEnabled() {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: fcpb.CIDRRangesToPrefixes(pbRateLimiter.GetClientCidr()),
		RPS:           pbRateLimiter.GetRps(),
		Enabled:       pbRateLimiter.GetEnabled(),
	}, respSzEst)
}

// accessToInternal converts protobuf access settings to an internal structure.
// If x is nil, toInternal returns [access.EmptyProfile].  If pbAccess is not
// nil cons must not be nil.
func accessToInternal(pbAccess *fcpb.Access, cons *access.ProfileConstructor) (a access.Profile) {
	if pbAccess == nil {
		return access.EmptyProfile{}
	}

	allowedASN := pbAccess.GetAllowlistAsn()
	blockedASN := pbAccess.GetBlocklistAsn()

	return cons.New(&access.ProfileConfig{
		AllowedNets:          fcpb.CIDRRangesToPrefixes(pbAccess.GetAllowlistCidr()),
		BlockedNets:          fcpb.CIDRRangesToPrefixes(pbAccess.GetBlocklistCidr()),
		AllowedASN:           agdprotobuf.UnsafelyConvertUint32Slice[uint32, geoip.ASN](allowedASN),
		BlockedASN:           agdprotobuf.UnsafelyConvertUint32Slice[uint32, geoip.ASN](blockedASN),
		BlocklistDomainRules: pbAccess.GetBlocklistDomainRules(),
		StandardEnabled:      pbAccess.GetStandardEnabled(),
	})
}

// profilesToProtobuf converts a slice of profiles to protobuf structures.
func profilesToProtobuf(profiles []*agd.Profile) (pbProfiles []*fcpb.Profile) {
	pbProfiles = make([]*fcpb.Profile, 0, len(profiles))
	for i, p := range profiles {
		if p == nil {
			panic(fmt.Errorf("converting profiles: at index %d: %w", i, errors.ErrNoValue))
		}

		pbProfiles = append(pbProfiles, profileToProtobuf(p))
	}

	return pbProfiles
}

// profileToProtobuf converts a profile to protobuf.  p must not be nil.
func profileToProtobuf(p *agd.Profile) (pbProf *fcpb.Profile) {
	defer func() {
		err := errors.FromRecovered(recover())
		if err != nil {
			// Repanic adding the profile information for easier debugging.
			panic(fmt.Errorf("converting profile %q: %w", p.ID, err))
		}
	}()

	pbProfBuilder := &fcpb.Profile_builder{
		CustomDomains: customDomainsToProtobuf(p.CustomDomains),
		FilterConfig:  filterConfigToProtobuf(p.FilterConfig),
		Access:        accessToProtobuf(p.Access.Config()),
		Ratelimiter:   ratelimiterToProtobuf(p.Ratelimiter.Config()),
		AccountId:     string(p.AccountID),
		ProfileId:     string(p.ID),
		DeviceIds: agdprotobuf.UnsafelyConvertStrSlice[agd.DeviceID, string](
			p.DeviceIDs.Values(),
		),
		FilteredResponseTtl: durationpb.New(p.FilteredResponseTTL),
		AutoDevicesEnabled:  p.AutoDevicesEnabled,
		BlockChromePrefetch: p.BlockChromePrefetch,
		BlockFirefoxCanary:  p.BlockFirefoxCanary,
		BlockPrivateRelay:   p.BlockPrivateRelay,
		Deleted:             p.Deleted,
		FilteringEnabled:    p.FilteringEnabled,
		IpLogEnabled:        p.IPLogEnabled,
		QueryLogEnabled:     p.QueryLogEnabled,
	}

	setBlockingMode(pbProfBuilder, p.BlockingMode)
	setAdultBlockingMode(pbProfBuilder, p.AdultBlockingMode)
	setSafeBrowsingBlockingMode(pbProfBuilder, p.SafeBrowsingBlockingMode)

	return pbProfBuilder.Build()
}

// customDomainsToProtobuf converts the custom-domains configuration to
// protobuf.  acd must not be nil.
func customDomainsToProtobuf(acd *agd.AccountCustomDomains) (pbACD *fcpb.AccountCustomDomains) {
	return fcpb.AccountCustomDomains_builder{
		Domains: customDomainConfigsToProtobuf(acd.Domains),
		Enabled: acd.Enabled,
	}.Build()
}

// customDomainConfigsToProtobuf converts the configuration of custom-domain
// sets to protobuf.
func customDomainConfigsToProtobuf(
	confs []*agd.CustomDomainConfig,
) (pbConfs []*fcpb.CustomDomainConfig) {
	l := len(confs)
	if l == 0 {
		return nil
	}

	pbConfs = make([]*fcpb.CustomDomainConfig, 0, l)
	for i, c := range confs {
		conf := fcpb.CustomDomainConfig_builder{
			Domains: slices.Clone(c.Domains),
		}.Build()

		switch s := c.State.(type) {
		case *agd.CustomDomainStateCurrent:
			curr := fcpb.CustomDomainConfig_StateCurrent_builder{
				NotBefore: timestamppb.New(s.NotBefore),
				NotAfter:  timestamppb.New(s.NotAfter),
				CertName:  string(s.CertName),
				Enabled:   s.Enabled,
			}.Build()

			conf.SetStateCurrent(curr)

		case *agd.CustomDomainStatePending:
			pend := fcpb.CustomDomainConfig_StatePending_builder{
				Expire:        timestamppb.New(s.Expire),
				WellKnownPath: s.WellKnownPath,
			}.Build()

			conf.SetStatePending(pend)
		default:
			panic(fmt.Errorf(
				"at index %d: custom domain state: %T(%[2]v): %w",
				i,
				s,
				errors.ErrBadEnumValue,
			))
		}

		pbConfs = append(pbConfs, conf)
	}

	return pbConfs
}

// filterConfigToProtobuf converts the filtering configuration to protobuf.  c
// must not be nil.
func filterConfigToProtobuf(c *filter.ConfigClient) (fc *fcpb.FilterConfig) {
	var rules []string
	if c.Custom.Enabled {
		filterRules := c.Custom.Filter.Rules()
		rules = agdprotobuf.UnsafelyConvertStrSlice[filter.RuleText, string](filterRules)
	}

	custom := fcpb.FilterConfig_Custom_builder{
		Rules:   rules,
		Enabled: c.Custom.Enabled,
	}.Build()

	categoryFilter := fcpb.FilterConfig_CategoryFilter_builder{
		Ids: agdprotobuf.UnsafelyConvertStrSlice[
			filter.CategoryID,
			string,
		](c.Parental.Categories.IDs),
		Enabled: c.Parental.Categories.Enabled,
	}.Build()

	parental := fcpb.FilterConfig_Parental_builder{
		PauseSchedule:  scheduleToProtobuf(c.Parental.PauseSchedule),
		CategoryFilter: categoryFilter,
		BlockedServices: agdprotobuf.UnsafelyConvertStrSlice[filter.BlockedServiceID, string](
			c.Parental.BlockedServices,
		),
		Enabled:                  c.Parental.Enabled,
		AdultBlockingEnabled:     c.Parental.AdultBlockingEnabled,
		SafeSearchGeneralEnabled: c.Parental.SafeSearchGeneralEnabled,
		SafeSearchYoutubeEnabled: c.Parental.SafeSearchYouTubeEnabled,
	}.Build()

	ruleList := fcpb.FilterConfig_RuleList_builder{
		Ids:     agdprotobuf.UnsafelyConvertStrSlice[filter.ID, string](c.RuleList.IDs),
		Enabled: c.RuleList.Enabled,
	}.Build()

	safeBrowsing := fcpb.FilterConfig_SafeBrowsing_builder{
		Enabled:                       c.SafeBrowsing.Enabled,
		DangerousDomainsEnabled:       c.SafeBrowsing.DangerousDomainsEnabled,
		NewlyRegisteredDomainsEnabled: c.SafeBrowsing.NewlyRegisteredDomainsEnabled,
	}.Build()

	return fcpb.FilterConfig_builder{
		Custom:       custom,
		Parental:     parental,
		RuleList:     ruleList,
		SafeBrowsing: safeBrowsing,
	}.Build()
}

// scheduleToProtobuf converts schedule configuration to protobuf.  If c is nil,
// conf is nil.
func scheduleToProtobuf(c *filter.ConfigSchedule) (conf *fcpb.FilterConfig_Schedule) {
	if c == nil {
		return nil
	}

	return fcpb.FilterConfig_Schedule_builder{
		TimeZone: c.TimeZone.String(),
		Week: fcpb.FilterConfig_WeeklySchedule_builder{
			Mon: dayIntervalToProtobuf(c.Week[time.Monday]),
			Tue: dayIntervalToProtobuf(c.Week[time.Tuesday]),
			Wed: dayIntervalToProtobuf(c.Week[time.Wednesday]),
			Thu: dayIntervalToProtobuf(c.Week[time.Thursday]),
			Fri: dayIntervalToProtobuf(c.Week[time.Friday]),
			Sat: dayIntervalToProtobuf(c.Week[time.Saturday]),
			Sun: dayIntervalToProtobuf(c.Week[time.Sunday]),
		}.Build(),
	}.Build()
}

// dayIntervalToProtobuf converts a daily schedule interval to protobuf.  If i
// is nil, ivl is nil.
func dayIntervalToProtobuf(i *filter.DayInterval) (ivl *fcpb.DayInterval) {
	if i == nil {
		return nil
	}

	return fcpb.DayInterval_builder{
		Start: uint32(i.Start),
		End:   uint32(i.End),
	}.Build()
}

// accessToProtobuf converts access settings to protobuf structure.  if c is
// nil, ac is nil.
func accessToProtobuf(c *access.ProfileConfig) (ac *fcpb.Access) {
	if c == nil {
		return nil
	}

	allowedASNs := agdprotobuf.UnsafelyConvertUint32Slice[geoip.ASN, uint32](c.AllowedASN)
	blockedASNs := agdprotobuf.UnsafelyConvertUint32Slice[geoip.ASN, uint32](c.BlockedASN)

	return fcpb.Access_builder{
		AllowlistAsn:         allowedASNs,
		AllowlistCidr:        prefixesToProtobuf(c.AllowedNets),
		BlocklistAsn:         blockedASNs,
		BlocklistCidr:        prefixesToProtobuf(c.BlockedNets),
		BlocklistDomainRules: c.BlocklistDomainRules,
		StandardEnabled:      c.StandardEnabled,
	}.Build()
}

// prefixesToProtobuf converts slice of [netip.Prefix] to protobuf structure.
// nets must be valid.
func prefixesToProtobuf(nets []netip.Prefix) (cidrs []*fcpb.CidrRange) {
	for _, n := range nets {
		cidr := fcpb.CidrRange_builder{
			Address: n.Addr().AsSlice(),
			// #nosec G115 -- Assume that the prefixes from profiledb are always
			// valid.
			Prefix: uint32(n.Bits()),
		}.Build()

		cidrs = append(cidrs, cidr)
	}

	return cidrs
}

// setBlockingMode populates protobuf profile builder with a blocking-mode
// sum-type.
//
// TODO(d.kolyshev):  DRY with setProtobufAdultBlockingMode and
// setProtobufSafeBrowsingBlockingMode.
func setBlockingMode(pb *fcpb.Profile_builder, m dnsmsg.BlockingMode) {
	switch m := m.(type) {
	case *dnsmsg.BlockingModeCustomIP:
		pb.BlockingModeCustomIp = fcpb.BlockingModeCustomIP_builder{
			Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
			Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
		}.Build()
	case *dnsmsg.BlockingModeNXDOMAIN:
		pb.BlockingModeNxdomain = &fcpb.BlockingModeNXDOMAIN{}
	case *dnsmsg.BlockingModeNullIP:
		pb.BlockingModeNullIp = &fcpb.BlockingModeNullIP{}
	case *dnsmsg.BlockingModeREFUSED:
		pb.BlockingModeRefused = &fcpb.BlockingModeREFUSED{}
	default:
		panic(fmt.Errorf("bad blocking mode %T(%[1]v)", m))
	}
}

// setAdultBlockingMode populates protobuf profile builder with a blocking-mode
// sum-type.
func setAdultBlockingMode(pb *fcpb.Profile_builder, m dnsmsg.BlockingMode) {
	switch m := m.(type) {
	case nil:
		return
	case *dnsmsg.BlockingModeCustomIP:
		pb.AdultBlockingModeCustomIp = fcpb.BlockingModeCustomIP_builder{
			Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
			Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
		}.Build()
	case *dnsmsg.BlockingModeNXDOMAIN:
		pb.AdultBlockingModeNxdomain = &fcpb.BlockingModeNXDOMAIN{}
	case *dnsmsg.BlockingModeNullIP:
		pb.AdultBlockingModeNullIp = &fcpb.BlockingModeNullIP{}
	case *dnsmsg.BlockingModeREFUSED:
		pb.AdultBlockingModeRefused = &fcpb.BlockingModeREFUSED{}
	default:
		panic(fmt.Errorf("bad adult blocking mode %T(%[1]v)", m))
	}
}

// setSafeBrowsingBlockingMode populates protobuf profile builder with a
// blocking-mode sum-type.
func setSafeBrowsingBlockingMode(pb *fcpb.Profile_builder, m dnsmsg.BlockingMode) {
	switch m := m.(type) {
	case nil:
		return
	case *dnsmsg.BlockingModeCustomIP:
		pb.SafeBrowsingBlockingModeCustomIp = fcpb.BlockingModeCustomIP_builder{
			Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
			Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
		}.Build()
	case *dnsmsg.BlockingModeNXDOMAIN:
		pb.SafeBrowsingBlockingModeNxdomain = &fcpb.BlockingModeNXDOMAIN{}
	case *dnsmsg.BlockingModeNullIP:
		pb.SafeBrowsingBlockingModeNullIp = &fcpb.BlockingModeNullIP{}
	case *dnsmsg.BlockingModeREFUSED:
		pb.SafeBrowsingBlockingModeRefused = &fcpb.BlockingModeREFUSED{}
	default:
		panic(fmt.Errorf("bad safe browsing blocking mode %T(%[1]v)", m))
	}
}

// ratelimiterToProtobuf converts the rate-limit settings to protobuf.  if c is
// nil, r is nil.
func ratelimiterToProtobuf(c *agd.RatelimitConfig) (r *fcpb.Ratelimiter) {
	if c == nil {
		return nil
	}

	return fcpb.Ratelimiter_builder{
		ClientCidr: prefixesToProtobuf(c.ClientSubnets),
		Rps:        c.RPS,
		Enabled:    c.Enabled,
	}.Build()
}
