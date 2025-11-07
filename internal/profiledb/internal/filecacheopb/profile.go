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
)

// profilesToInternal converts protobuf profile structures into internal ones.
// baseCustomLogger and cons must not be nil.
//
//lint:ignore U1000 TODO(f.setrakov): Use.
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

// configParentalToInternal converts filter config's protobuf parental config
// structures to internal ones.  pbFltConf must not be nil.
func configParentalToInternal(
	pbFltConf *fcpb.FilterConfig,
	schedule *filter.ConfigSchedule,
) (c *filter.ConfigParental) {
	parental := pbFltConf.GetParental()

	return &filter.ConfigParental{
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
