// Package filecachepb contains the protobuf structures for the profile cache.
package filecachepb

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// toInternal converts the protobuf-encoded data into a cache structure.  fc
// baseCustomLogger, and cons must not be nil.
func toInternal(
	fc *FileCache,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (c *internal.FileCache, err error) {
	profiles, err := profilesToInternal(fc.Profiles, baseCustomLogger, cons, respSzEst)
	if err != nil {
		return nil, fmt.Errorf("converting profiles: %w", err)
	}

	devices, err := devicesFromProtobuf(fc.Devices)
	if err != nil {
		return nil, fmt.Errorf("converting devices: %w", err)
	}

	return &internal.FileCache{
		SyncTime: fc.SyncTime.AsTime(),
		Profiles: profiles,
		Devices:  devices,
		Version:  fc.Version,
	}, nil
}

// toProtobuf converts the cache structure into protobuf structure for encoding.
func toProtobuf(c *internal.FileCache) (pbFileCache *FileCache) {
	return &FileCache{
		SyncTime: timestamppb.New(c.SyncTime),
		Profiles: profilesToProtobuf(c.Profiles),
		Devices:  devicesToProtobuf(c.Devices),
		Version:  c.Version,
	}
}

// profilesToInternal converts protobuf profile structures into internal ones.
// baseCustomLogger and cons must not be nil.
func profilesToInternal(
	pbProfiles []*Profile,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (profiles []*agd.Profile, err error) {
	profiles = make([]*agd.Profile, 0, len(pbProfiles))
	for i, pbProf := range pbProfiles {
		var prof *agd.Profile
		prof, err = pbProf.toInternal(baseCustomLogger, cons, respSzEst)
		if err != nil {
			return nil, fmt.Errorf("profile at index %d: %w", i, err)
		}

		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// toInternal converts a protobuf profile structure to an internal one.
// baseCustomLogger and cons must not be nil.
func (x *Profile) toInternal(
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (prof *agd.Profile, err error) {
	adultBlockingMode, err := adultBlockingModeToInternal(x.AdultBlockingMode)
	if err != nil {
		return nil, fmt.Errorf("adult blocking mode: %w", err)
	}

	safeBrowsingBlockingMode, err := safeBrowsingBlockingModeToInternal(x.SafeBrowsingBlockingMode)
	if err != nil {
		return nil, fmt.Errorf("safe browsing blocking mode: %w", err)
	}

	m, err := blockingModeToInternal(x.BlockingMode)
	if err != nil {
		return nil, fmt.Errorf("blocking mode: %w", err)
	}

	pbFltConf := x.FilterConfig
	schedule, err := pbFltConf.Parental.PauseSchedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("pause schedule: %w", err)
	}

	// Consider the rules to have been prevalidated.
	rules := agdprotobuf.UnsafelyConvertStrSlice[string, filter.RuleText](pbFltConf.Custom.Rules)

	var flt filter.Custom
	if len(rules) > 0 {
		flt = custom.New(&custom.Config{
			Logger: baseCustomLogger.With("client_id", x.ProfileId),
			Rules:  rules,
		})
	}

	customDomainConfs, err := customDomainsToInternal(x.CustomDomains.Domains)
	if err != nil {
		return nil, fmt.Errorf("custom domain configs: %w", err)
	}

	customDomains := &agd.AccountCustomDomains{
		Domains: customDomainConfs,
		Enabled: x.CustomDomains.Enabled,
	}

	fltConf := &filter.ConfigClient{
		Custom: &filter.ConfigCustom{
			Filter:  flt,
			Enabled: pbFltConf.Custom.Enabled,
		},
		Parental: &filter.ConfigParental{
			Categories:    categoriesToInternal(pbFltConf),
			PauseSchedule: schedule,
			// Consider blocked-service IDs to have been prevalidated.
			BlockedServices: agdprotobuf.UnsafelyConvertStrSlice[string, filter.BlockedServiceID](
				pbFltConf.Parental.BlockedServices,
			),
			Enabled:                  pbFltConf.Parental.Enabled,
			AdultBlockingEnabled:     pbFltConf.Parental.AdultBlockingEnabled,
			SafeSearchGeneralEnabled: pbFltConf.Parental.SafeSearchGeneralEnabled,
			SafeSearchYouTubeEnabled: pbFltConf.Parental.SafeSearchYoutubeEnabled,
		},
		RuleList: &filter.ConfigRuleList{
			// Consider rule-list IDs to have been prevalidated.
			IDs:     agdprotobuf.UnsafelyConvertStrSlice[string, filter.ID](pbFltConf.RuleList.Ids),
			Enabled: pbFltConf.RuleList.Enabled,
		},
		SafeBrowsing: &filter.ConfigSafeBrowsing{
			Enabled:                       pbFltConf.SafeBrowsing.Enabled,
			DangerousDomainsEnabled:       pbFltConf.SafeBrowsing.DangerousDomainsEnabled,
			NewlyRegisteredDomainsEnabled: pbFltConf.SafeBrowsing.NewlyRegisteredDomainsEnabled,
		},
	}

	return &agd.Profile{
		CustomDomains: customDomains,
		FilterConfig:  fltConf,

		Access:                   x.Access.toInternal(cons),
		AdultBlockingMode:        adultBlockingMode,
		BlockingMode:             m,
		SafeBrowsingBlockingMode: safeBrowsingBlockingMode,
		Ratelimiter:              x.Ratelimiter.toInternal(respSzEst),

		AccountID: agd.AccountID(x.AccountId),
		ID:        agd.ProfileID(x.ProfileId),

		// Consider device IDs to have been prevalidated.
		DeviceIDs: container.NewMapSet(
			agdprotobuf.UnsafelyConvertStrSlice[string, agd.DeviceID](x.DeviceIds)...,
		),

		// Consider rule-list IDs to have been prevalidated.
		FilteredResponseTTL: x.FilteredResponseTtl.AsDuration(),

		AutoDevicesEnabled:  x.AutoDevicesEnabled,
		BlockChromePrefetch: x.BlockChromePrefetch,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		Deleted:             x.Deleted,
		FilteringEnabled:    x.FilteringEnabled,
		IPLogEnabled:        x.IpLogEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
	}, nil
}

// categoriesToInternal converts filter config's protobuf category filter to
// internal one.  pbFltConf must not be nil.
func categoriesToInternal(pbFltConf *FilterConfig) (c *filter.ConfigCategories) {
	pbCatFltr := pbFltConf.Parental.CategoryFilter
	if pbCatFltr == nil && pbFltConf.CategoryFilter != nil {
		// TODO(d.kolyshev):  Remove after moving deprecated profile categories
		// in [internal/profiledb/internal.FileCacheVersion] 19.
		pbCatFltr = pbFltConf.CategoryFilter
	}

	return pbCatFltr.toInternal()
}

// toInternal converts filter config's protobuf category filter structure to
// internal one.  If x is nil, returns a disabled config.
func (x *FilterConfig_CategoryFilter) toInternal() (c *filter.ConfigCategories) {
	if x == nil {
		return &filter.ConfigCategories{
			Enabled: false,
		}
	}

	// Consider the categories to have been prevalidated.
	ids := agdprotobuf.UnsafelyConvertStrSlice[string, filter.CategoryID](x.GetIds())
	return &filter.ConfigCategories{
		IDs:     ids,
		Enabled: x.GetEnabled(),
	}
}

// toInternal converts a protobuf protection-schedule structure to an internal
// one.  If x is nil, c is nil.
func (x *FilterConfig_Schedule) toInternal() (c *filter.ConfigSchedule, err error) {
	if x == nil {
		return nil, nil
	}

	loc, err := agdtime.LoadLocation(x.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("time zone: %w", err)
	}

	return &filter.ConfigSchedule{
		// Consider the lengths to be prevalidated.
		Week: &filter.WeeklySchedule{
			time.Monday:    x.Week.Mon.toInternal(),
			time.Tuesday:   x.Week.Tue.toInternal(),
			time.Wednesday: x.Week.Wed.toInternal(),
			time.Thursday:  x.Week.Thu.toInternal(),
			time.Friday:    x.Week.Fri.toInternal(),
			time.Saturday:  x.Week.Sat.toInternal(),
			time.Sunday:    x.Week.Sun.toInternal(),
		},
		TimeZone: loc,
	}, nil
}

// toInternal converts a protobuf day interval to an internal one.  If x is nil,
// i is nil.
func (x *DayInterval) toInternal() (i *filter.DayInterval) {
	if x == nil {
		return nil
	}

	return &filter.DayInterval{
		// #nosec G115 -- The values put in these are always from uint16s.
		Start: uint16(x.Start),
		// #nosec G115 -- The values put in these are always from uint16s.
		End: uint16(x.End),
	}
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
// TODO(d.kolyshev):  DRY with adultBlockingModeToInternal and
// safeBrowsingBlockingModeToInternal.
func blockingModeToInternal(pbm isProfile_BlockingMode) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case *Profile_BlockingModeCustomIp:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(pbm.BlockingModeCustomIp.Ipv4)
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(pbm.BlockingModeCustomIp.Ipv6)
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case *Profile_BlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *Profile_BlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *Profile_BlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm)
	}
}

// adultBlockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
func adultBlockingModeToInternal(
	pbm isProfile_AdultBlockingMode,
) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return nil, nil
	case *Profile_AdultBlockingModeCustomIp:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(pbm.AdultBlockingModeCustomIp.Ipv4)
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(pbm.AdultBlockingModeCustomIp.Ipv6)
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case *Profile_AdultBlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *Profile_AdultBlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *Profile_AdultBlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb adult blocking mode %T(%[1]v)", pbm)
	}
}

// safeBrowsingBlockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
func safeBrowsingBlockingModeToInternal(
	pbm isProfile_SafeBrowsingBlockingMode,
) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return nil, nil
	case *Profile_SafeBrowsingBlockingModeCustomIp:
		var ipv4 []netip.Addr
		ipv4, err = agdprotobuf.ByteSlicesToIPs(pbm.SafeBrowsingBlockingModeCustomIp.Ipv4)
		if err != nil {
			return nil, fmt.Errorf("bad v4 custom ips: %w", err)
		}

		var ipv6 []netip.Addr
		ipv6, err = agdprotobuf.ByteSlicesToIPs(pbm.SafeBrowsingBlockingModeCustomIp.Ipv6)
		if err != nil {
			return nil, fmt.Errorf("bad v6 custom ips: %w", err)
		}

		return &dnsmsg.BlockingModeCustomIP{
			IPv4: ipv4,
			IPv6: ipv6,
		}, nil
	case *Profile_SafeBrowsingBlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *Profile_SafeBrowsingBlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *Profile_SafeBrowsingBlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb safe browsing blocking mode %T(%[1]v)", pbm)
	}
}

// customDomainsToInternal converts protobuf custom-domain configurations to
// internal ones.
func customDomainsToInternal(
	pbConfs []*CustomDomainConfig,
) (confs []*agd.CustomDomainConfig, err error) {
	l := len(pbConfs)
	if l == 0 {
		return nil, nil
	}

	confs = make([]*agd.CustomDomainConfig, 0, l)
	for i, pbConf := range pbConfs {
		var c *agd.CustomDomainConfig
		c, err = pbConf.toInternal()
		if err != nil {
			return nil, fmt.Errorf("at index %d: %w", i, err)
		}

		confs = append(confs, c)
	}

	return confs, nil
}

// toInternal converts a protobuf custom-domain config to an internal one.
func (x *CustomDomainConfig) toInternal() (c *agd.CustomDomainConfig, err error) {
	var state agd.CustomDomainState
	switch s := x.State.(type) {
	case *CustomDomainConfig_StateCurrent_:
		state = &agd.CustomDomainStateCurrent{
			NotBefore: s.StateCurrent.NotBefore.AsTime(),
			NotAfter:  s.StateCurrent.NotAfter.AsTime(),
			// Consider certificate names to have been prevalidated.
			CertName: agd.CertificateName(s.StateCurrent.CertName),
			Enabled:  s.StateCurrent.Enabled,
		}
	case *CustomDomainConfig_StatePending_:
		state = &agd.CustomDomainStatePending{
			Expire:        s.StatePending.Expire.AsTime(),
			WellKnownPath: s.StatePending.WellKnownPath,
		}
	default:
		return nil, fmt.Errorf("pb custom domain state: %T(%[1]v): %w", s, errors.ErrBadEnumValue)
	}

	return &agd.CustomDomainConfig{
		State:   state,
		Domains: slices.Clone(x.Domains),
	}, nil
}

// devicesToInternal converts protobuf device structures into internal ones.
func devicesFromProtobuf(pbDevices []*Device) (devices []*agd.Device, err error) {
	devices = make([]*agd.Device, 0, len(pbDevices))
	for i, pbDev := range pbDevices {
		var dev *agd.Device
		dev, err = pbDev.toInternal()
		if err != nil {
			return nil, fmt.Errorf("device at index %d: %w", i, err)
		}

		devices = append(devices, dev)
	}

	return devices, nil
}

// toInternal converts a protobuf device structure to an internal one.
func (x *Device) toInternal() (d *agd.Device, err error) {
	var linkedIP netip.Addr
	err = linkedIP.UnmarshalBinary(x.LinkedIp)
	if err != nil {
		return nil, fmt.Errorf("linked ip: %w", err)
	}

	var dedicatedIPs []netip.Addr
	dedicatedIPs, err = agdprotobuf.ByteSlicesToIPs(x.DedicatedIps)
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	auth, err := x.Authentication.toInternal()
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", x.DeviceId, err)
	}

	return &agd.Device{
		Auth: auth,
		// Consider device IDs to have been prevalidated.
		ID:       agd.DeviceID(x.DeviceId),
		LinkedIP: linkedIP,
		// Consider device names to have been prevalidated.
		Name: agd.DeviceName(x.DeviceName),
		// Consider lowercase HumanIDs to have been prevalidated.
		HumanIDLower:     agd.HumanIDLower(x.HumanIdLower),
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: x.FilteringEnabled,
	}, nil
}

// toInternal converts a protobuf auth settings structure to an internal one.
// If x is nil, toInternal returns non-nil settings with Enabled field set to
// false, otherwise it sets the Enabled field to true.
func (x *AuthenticationSettings) toInternal() (s *agd.AuthSettings, err error) {
	if x == nil {
		return &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		}, nil
	}

	ph, err := dohPasswordToInternal(x.DohPasswordHash)
	if err != nil {
		return nil, fmt.Errorf("password hash: %w", err)
	}

	return &agd.AuthSettings{
		PasswordHash: ph,
		Enabled:      true,
		DoHAuthOnly:  x.DohAuthOnly,
	}, nil
}

// dohPasswordToInternal converts a protobuf DoH password hash sum-type to an
// internal one.  If pbp is nil, it returns nil.
func dohPasswordToInternal(
	pbp isAuthenticationSettings_DohPasswordHash,
) (p agdpasswd.Authenticator, err error) {
	switch pbp := pbp.(type) {
	case nil:
		return agdpasswd.AllowAuthenticator{}, nil
	case *AuthenticationSettings_PasswordHashBcrypt:
		return agdpasswd.NewPasswordHashBcrypt(pbp.PasswordHashBcrypt), nil
	default:
		return nil, fmt.Errorf("bad pb auth doh password hash %T(%[1]v)", pbp)
	}
}

// toInternal converts a protobuf rate-limiting settings structure to an
// internal one.
func (x *Ratelimiter) toInternal(respSzEst datasize.ByteSize) (r agd.Ratelimiter) {
	if x == nil || !x.Enabled {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: cidrRangeToInternal(x.ClientCidr),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].  If x is not nil, mtrc must
// be non-nil.
func (x *Access) toInternal(cons *access.ProfileConstructor) (a access.Profile) {
	if x == nil {
		return access.EmptyProfile{}
	}

	return cons.New(&access.ProfileConfig{
		AllowedNets:          cidrRangeToInternal(x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
		StandardEnabled:      x.StandardEnabled,
	})
}

// cidrRangeToInternal is a helper that converts a slice of CidrRange to the
// slice of [netip.Prefix].
func cidrRangeToInternal(cidrs []*CidrRange) (out []netip.Prefix) {
	for _, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.Address)
		if !ok {
			// Should never happen.
			panic(fmt.Errorf("bad address: %v", c.Address))
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

// profilesToProtobuf converts a slice of profiles to protobuf structures.
func profilesToProtobuf(profiles []*agd.Profile) (pbProfiles []*Profile) {
	pbProfiles = make([]*Profile, 0, len(profiles))
	for i, p := range profiles {
		if p == nil {
			panic(fmt.Errorf("converting profiles: at index %d: %w", i, errors.ErrNoValue))
		}

		pbProfiles = append(pbProfiles, profileToProtobuf(p))
	}

	return pbProfiles
}

// profileToProtobuf converts a profile to protobuf.  p must not be nil.
func profileToProtobuf(p *agd.Profile) (pbProf *Profile) {
	defer func() {
		err := errors.FromRecovered(recover())
		if err != nil {
			// Repanic adding the profile information for easier debugging.
			panic(fmt.Errorf("converting profile %q: %w", p.ID, err))
		}
	}()

	return &Profile{
		CustomDomains:            customDomainsToProtobuf(p.CustomDomains),
		FilterConfig:             filterConfigToProtobuf(p.FilterConfig),
		Access:                   accessToProtobuf(p.Access.Config()),
		AdultBlockingMode:        adultBlockingModeToProtobuf(p.AdultBlockingMode),
		BlockingMode:             blockingModeToProtobuf(p.BlockingMode),
		SafeBrowsingBlockingMode: safeBrowsingBlockingModeToProtobuf(p.SafeBrowsingBlockingMode),
		Ratelimiter:              ratelimiterToProtobuf(p.Ratelimiter.Config()),
		AccountId:                string(p.AccountID),
		ProfileId:                string(p.ID),
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
}

// customDomainsToProtobuf converts the custom-domains configuration to
// protobuf.
func customDomainsToProtobuf(acd *agd.AccountCustomDomains) (pbACD *AccountCustomDomains) {
	return &AccountCustomDomains{
		Domains: customDomainConfigsToProtobuf(acd.Domains),
		Enabled: acd.Enabled,
	}
}

// customDomainConfigsToProtobuf converts the configuration of custom-domain
// sets to protobuf.
func customDomainConfigsToProtobuf(
	confs []*agd.CustomDomainConfig,
) (pbConfs []*CustomDomainConfig) {
	l := len(confs)
	if l == 0 {
		return nil
	}

	pbConfs = make([]*CustomDomainConfig, 0, l)
	for i, c := range confs {
		var state isCustomDomainConfig_State
		switch s := c.State.(type) {
		case *agd.CustomDomainStateCurrent:
			curr := &CustomDomainConfig_StateCurrent{
				NotBefore: timestamppb.New(s.NotBefore),
				NotAfter:  timestamppb.New(s.NotAfter),
				CertName:  string(s.CertName),
				Enabled:   s.Enabled,
			}

			state = &CustomDomainConfig_StateCurrent_{
				StateCurrent: curr,
			}
		case *agd.CustomDomainStatePending:
			pend := &CustomDomainConfig_StatePending{
				Expire:        timestamppb.New(s.Expire),
				WellKnownPath: s.WellKnownPath,
			}

			state = &CustomDomainConfig_StatePending_{
				StatePending: pend,
			}
		default:
			panic(fmt.Errorf(
				"at index %d: custom domain state: %T(%[2]v): %w",
				i,
				s,
				errors.ErrBadEnumValue,
			))
		}

		pbConfs = append(pbConfs, &CustomDomainConfig{
			State:   state,
			Domains: slices.Clone(c.Domains),
		})
	}

	return pbConfs
}

// filterConfigToProtobuf converts the filtering configuration to protobuf.
func filterConfigToProtobuf(c *filter.ConfigClient) (fc *FilterConfig) {
	var rules []string
	if c.Custom.Enabled {
		rules = agdprotobuf.UnsafelyConvertStrSlice[filter.RuleText, string](c.Custom.Filter.Rules())
	}

	parentalCategories := &FilterConfig_CategoryFilter{
		Ids: agdprotobuf.UnsafelyConvertStrSlice[filter.CategoryID, string](
			c.Parental.Categories.IDs,
		),
		Enabled: c.Parental.Categories.Enabled,
	}

	return &FilterConfig{
		Custom: &FilterConfig_Custom{
			Rules:   rules,
			Enabled: c.Custom.Enabled,
		},
		Parental: &FilterConfig_Parental{
			PauseSchedule:  scheduleToProtobuf(c.Parental.PauseSchedule),
			CategoryFilter: parentalCategories,
			BlockedServices: agdprotobuf.UnsafelyConvertStrSlice[filter.BlockedServiceID, string](
				c.Parental.BlockedServices,
			),
			Enabled:                  c.Parental.Enabled,
			AdultBlockingEnabled:     c.Parental.AdultBlockingEnabled,
			SafeSearchGeneralEnabled: c.Parental.SafeSearchGeneralEnabled,
			SafeSearchYoutubeEnabled: c.Parental.SafeSearchYouTubeEnabled,
		},
		RuleList: &FilterConfig_RuleList{
			Ids:     agdprotobuf.UnsafelyConvertStrSlice[filter.ID, string](c.RuleList.IDs),
			Enabled: c.RuleList.Enabled,
		},
		SafeBrowsing: &FilterConfig_SafeBrowsing{
			Enabled:                       c.SafeBrowsing.Enabled,
			DangerousDomainsEnabled:       c.SafeBrowsing.DangerousDomainsEnabled,
			NewlyRegisteredDomainsEnabled: c.SafeBrowsing.NewlyRegisteredDomainsEnabled,
		},
	}
}

// scheduleToProtobuf converts schedule configuration to protobuf.  If c is nil,
// conf is nil.
func scheduleToProtobuf(c *filter.ConfigSchedule) (conf *FilterConfig_Schedule) {
	if c == nil {
		return nil
	}

	return &FilterConfig_Schedule{
		Week: &FilterConfig_WeeklySchedule{
			Mon: dayIntervalToProtobuf(c.Week[time.Monday]),
			Tue: dayIntervalToProtobuf(c.Week[time.Tuesday]),
			Wed: dayIntervalToProtobuf(c.Week[time.Wednesday]),
			Thu: dayIntervalToProtobuf(c.Week[time.Thursday]),
			Fri: dayIntervalToProtobuf(c.Week[time.Friday]),
			Sat: dayIntervalToProtobuf(c.Week[time.Saturday]),
			Sun: dayIntervalToProtobuf(c.Week[time.Sunday]),
		},
		TimeZone: c.TimeZone.String(),
	}
}

// dayIntervalToProtobuf converts a daily schedule interval to protobuf.  If i
// is nil, ivl is nil.
func dayIntervalToProtobuf(i *filter.DayInterval) (ivl *DayInterval) {
	if i == nil {
		return nil
	}

	return &DayInterval{
		Start: uint32(i.Start),
		End:   uint32(i.End),
	}
}

// accessToProtobuf converts access settings to protobuf structure.
func accessToProtobuf(c *access.ProfileConfig) (ac *Access) {
	if c == nil {
		return nil
	}

	var allowedASNs []uint32
	for _, asn := range c.AllowedASN {
		allowedASNs = append(allowedASNs, uint32(asn))
	}

	var blockedASNs []uint32
	for _, asn := range c.BlockedASN {
		blockedASNs = append(blockedASNs, uint32(asn))
	}

	return &Access{
		AllowlistAsn:         allowedASNs,
		AllowlistCidr:        prefixesToProtobuf(c.AllowedNets),
		BlocklistAsn:         blockedASNs,
		BlocklistCidr:        prefixesToProtobuf(c.BlockedNets),
		BlocklistDomainRules: c.BlocklistDomainRules,
		StandardEnabled:      c.StandardEnabled,
	}
}

// prefixesToProtobuf converts slice of [netip.Prefix] to protobuf structure.
// nets must be valid.
func prefixesToProtobuf(nets []netip.Prefix) (cidrs []*CidrRange) {
	for _, n := range nets {
		cidrs = append(cidrs, &CidrRange{
			Address: n.Addr().AsSlice(),
			// #nosec G115 -- Assume that the prefixes from profiledb are always
			// valid.
			Prefix: uint32(n.Bits()),
		})
	}

	return cidrs
}

// blockingModeToProtobuf converts a blocking-mode sum-type to a protobuf one.
//
// TODO(d.kolyshev):  DRY with adultBlockingModeToProtobuf and
// safeBrowsingBlockingModeToProtobuf.
func blockingModeToProtobuf(m dnsmsg.BlockingMode) (pbBlockingMode isProfile_BlockingMode) {
	switch m := m.(type) {
	case *dnsmsg.BlockingModeCustomIP:
		return &Profile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
				Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
			},
		}
	case *dnsmsg.BlockingModeNXDOMAIN:
		return &Profile_BlockingModeNxdomain{
			BlockingModeNxdomain: &BlockingModeNXDOMAIN{},
		}
	case *dnsmsg.BlockingModeNullIP:
		return &Profile_BlockingModeNullIp{
			BlockingModeNullIp: &BlockingModeNullIP{},
		}
	case *dnsmsg.BlockingModeREFUSED:
		return &Profile_BlockingModeRefused{
			BlockingModeRefused: &BlockingModeREFUSED{},
		}
	default:
		panic(fmt.Errorf("bad blocking mode %T(%[1]v)", m))
	}
}

// adultBlockingModeToProtobuf converts a blocking-mode sum-type to a protobuf
// one.
func adultBlockingModeToProtobuf(
	m dnsmsg.BlockingMode,
) (pbBlockingMode isProfile_AdultBlockingMode) {
	switch m := m.(type) {
	case nil:
		return nil
	case *dnsmsg.BlockingModeCustomIP:
		return &Profile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
				Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
			},
		}
	case *dnsmsg.BlockingModeNXDOMAIN:
		return &Profile_AdultBlockingModeNxdomain{
			AdultBlockingModeNxdomain: &BlockingModeNXDOMAIN{},
		}
	case *dnsmsg.BlockingModeNullIP:
		return &Profile_AdultBlockingModeNullIp{
			AdultBlockingModeNullIp: &BlockingModeNullIP{},
		}
	case *dnsmsg.BlockingModeREFUSED:
		return &Profile_AdultBlockingModeRefused{
			AdultBlockingModeRefused: &BlockingModeREFUSED{},
		}
	default:
		panic(fmt.Errorf("bad adult blocking mode %T(%[1]v)", m))
	}
}

// safeBrowsingBlockingModeToProtobuf converts a blocking-mode sum-type to a
// protobuf one.
func safeBrowsingBlockingModeToProtobuf(
	m dnsmsg.BlockingMode,
) (pbBlockingMode isProfile_SafeBrowsingBlockingMode) {
	switch m := m.(type) {
	case nil:
		return nil
	case *dnsmsg.BlockingModeCustomIP:
		return &Profile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: agdprotobuf.IPsToByteSlices(m.IPv4),
				Ipv6: agdprotobuf.IPsToByteSlices(m.IPv6),
			},
		}
	case *dnsmsg.BlockingModeNXDOMAIN:
		return &Profile_SafeBrowsingBlockingModeNxdomain{
			SafeBrowsingBlockingModeNxdomain: &BlockingModeNXDOMAIN{},
		}
	case *dnsmsg.BlockingModeNullIP:
		return &Profile_SafeBrowsingBlockingModeNullIp{
			SafeBrowsingBlockingModeNullIp: &BlockingModeNullIP{},
		}
	case *dnsmsg.BlockingModeREFUSED:
		return &Profile_SafeBrowsingBlockingModeRefused{
			SafeBrowsingBlockingModeRefused: &BlockingModeREFUSED{},
		}
	default:
		panic(fmt.Errorf("bad safe browsing blocking mode %T(%[1]v)", m))
	}
}

// ratelimiterToProtobuf converts the rate-limit settings to protobuf.
func ratelimiterToProtobuf(c *agd.RatelimitConfig) (r *Ratelimiter) {
	if c == nil {
		return nil
	}

	return &Ratelimiter{
		ClientCidr: prefixesToProtobuf(c.ClientSubnets),
		Rps:        c.RPS,
		Enabled:    c.Enabled,
	}
}

// devicesToProtobuf converts a slice of devices to protobuf structures.
func devicesToProtobuf(devices []*agd.Device) (pbDevices []*Device) {
	pbDevices = make([]*Device, 0, len(devices))
	for _, d := range devices {
		pbDevices = append(pbDevices, &Device{
			Authentication:   authToProtobuf(d.Auth),
			DeviceId:         string(d.ID),
			LinkedIp:         agdprotobuf.IPToBytes(d.LinkedIP),
			HumanIdLower:     string(d.HumanIDLower),
			DeviceName:       string(d.Name),
			DedicatedIps:     agdprotobuf.IPsToByteSlices(d.DedicatedIPs),
			FilteringEnabled: d.FilteringEnabled,
		})
	}

	return pbDevices
}

// authToProtobuf converts an auth device settings to a protobuf struct.
// Returns nil if the given settings have Enabled field set to false.
func authToProtobuf(s *agd.AuthSettings) (a *AuthenticationSettings) {
	if s == nil || !s.Enabled {
		return nil
	}

	return &AuthenticationSettings{
		DohAuthOnly:     s.DoHAuthOnly,
		DohPasswordHash: dohPasswordToProtobuf(s.PasswordHash),
	}
}

// dohPasswordToProtobuf converts an auth password hash sum-type to a protobuf
// one.
func dohPasswordToProtobuf(
	p agdpasswd.Authenticator,
) (pbp isAuthenticationSettings_DohPasswordHash) {
	switch p := p.(type) {
	// TODO(a.garipov):  Remove nil once we make sure that the caches on prod
	// are valid.
	case nil, agdpasswd.AllowAuthenticator:
		return nil
	case *agdpasswd.PasswordHashBcrypt:
		return &AuthenticationSettings_PasswordHashBcrypt{
			PasswordHashBcrypt: p.PasswordHash(),
		}
	default:
		panic(fmt.Errorf("bad password hash %T(%[1]v)", p))
	}
}
