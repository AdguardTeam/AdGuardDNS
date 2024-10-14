// Package filecachepb contains the protobuf structures for the profile cache.
package filecachepb

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/c2h5oh/datasize"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// toInternal converts the protobuf-encoded data into a cache structure.
func toInternal(fc *FileCache, respSzEst datasize.ByteSize) (c *internal.FileCache, err error) {
	profiles, err := profilesToInternal(fc.Profiles, respSzEst)
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
func profilesToInternal(
	pbProfiles []*Profile,
	respSzEst datasize.ByteSize,
) (profiles []*agd.Profile, err error) {
	profiles = make([]*agd.Profile, 0, len(pbProfiles))
	for i, pbProf := range pbProfiles {
		var prof *agd.Profile
		prof, err = pbProf.toInternal(respSzEst)
		if err != nil {
			return nil, fmt.Errorf("profile at index %d: %w", i, err)
		}

		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// toInternal converts a protobuf profile structure to an internal one.
func (x *Profile) toInternal(respSzEst datasize.ByteSize) (prof *agd.Profile, err error) {
	parental, err := x.Parental.toInternal()
	if err != nil {
		return nil, fmt.Errorf("parental: %w", err)
	}

	m, err := blockingModeToInternal(x.BlockingMode)
	if err != nil {
		return nil, fmt.Errorf("blocking mode: %w", err)
	}

	return &agd.Profile{
		Parental:     parental,
		Ratelimiter:  x.RateLimit.toInternal(respSzEst),
		BlockingMode: m,
		ID:           agd.ProfileID(x.ProfileId),
		UpdateTime:   x.UpdateTime.AsTime(),
		// Consider device IDs to have been prevalidated.
		DeviceIDs: unsafelyConvertStrSlice[string, agd.DeviceID](x.DeviceIds),
		// Consider rule-list IDs to have been prevalidated.
		RuleListIDs: unsafelyConvertStrSlice[string, agd.FilterListID](x.RuleListIds),
		// Consider rule-list IDs to have been prevalidated.
		CustomRules: unsafelyConvertStrSlice[string, agd.FilterRuleText](
			x.CustomRules,
		),
		FilteredResponseTTL: x.FilteredResponseTtl.AsDuration(),
		FilteringEnabled:    x.FilteringEnabled,
		SafeBrowsing:        x.SafeBrowsing.toInternal(),
		Access:              x.Access.toInternal(),
		RuleListsEnabled:    x.RuleListsEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
		Deleted:             x.Deleted,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
		IPLogEnabled:        x.IpLogEnabled,
		AutoDevicesEnabled:  x.AutoDevicesEnabled,
	}, nil
}

// toInternal converts a protobuf parental-settings structure to an internal
// one.
func (x *ParentalProtectionSettings) toInternal() (s *agd.ParentalProtectionSettings, err error) {
	if x == nil {
		return nil, nil
	}

	schedule, err := x.Schedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("schedule: %w", err)
	}

	return &agd.ParentalProtectionSettings{
		Schedule: schedule,
		// Consider block service IDs to have been prevalidated.
		BlockedServices: unsafelyConvertStrSlice[string, agd.BlockedServiceID](
			x.BlockedServices,
		),
		Enabled:           x.Enabled,
		BlockAdult:        x.BlockAdult,
		GeneralSafeSearch: x.GeneralSafeSearch,
		YoutubeSafeSearch: x.YoutubeSafeSearch,
	}, nil
}

// toInternal converts a protobuf protection-schedule structure to an internal
// one.
func (x *ParentalProtectionSchedule) toInternal() (s *agd.ParentalProtectionSchedule, err error) {
	if x == nil {
		return nil, nil
	}

	loc, err := agdtime.LoadLocation(x.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("time zone: %w", err)
	}

	return &agd.ParentalProtectionSchedule{
		// Consider the lengths to be prevalidated.
		Week: &agd.WeeklySchedule{
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Monday: {Start: uint16(x.Mon.Start), End: uint16(x.Mon.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Tuesday: {Start: uint16(x.Tue.Start), End: uint16(x.Tue.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Wednesday: {Start: uint16(x.Wed.Start), End: uint16(x.Wed.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Thursday: {Start: uint16(x.Thu.Start), End: uint16(x.Thu.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Friday: {Start: uint16(x.Fri.Start), End: uint16(x.Fri.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Saturday: {Start: uint16(x.Sat.Start), End: uint16(x.Sat.End)},
			// #nosec G115 -- The values put in these are always from uint16s.
			time.Sunday: {Start: uint16(x.Sun.Start), End: uint16(x.Sun.End)},
		},
		TimeZone: loc,
	}, nil
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
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
		return nil, nil
	case *AuthenticationSettings_PasswordHashBcrypt:
		return agdpasswd.NewPasswordHashBcrypt(pbp.PasswordHashBcrypt), nil
	default:
		return nil, fmt.Errorf("bad pb auth doh password hash %T(%[1]v)", pbp)
	}
}

// toInternal converts a protobuf rate-limiting settings structure to an
// internal one.
func (x *RateLimitSettings) toInternal(respSzEst datasize.ByteSize) (r agd.Ratelimiter) {
	if x == nil || !x.Enabled {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: cidrRangeToInternal(x.ClientCidr),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// toInternal converts a protobuf safe browsing settings structure to an
// internal one.
func (x *SafeBrowsingSettings) toInternal() (s *agd.SafeBrowsingSettings) {
	if x == nil {
		return nil
	}

	return &agd.SafeBrowsingSettings{
		Enabled:                     x.Enabled,
		BlockDangerousDomains:       x.BlockDangerousDomains,
		BlockNewlyRegisteredDomains: x.BlockNewlyRegisteredDomains,
	}
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].
func (x *AccessSettings) toInternal() (a access.Profile) {
	if x == nil {
		return access.EmptyProfile{}
	}

	return access.NewDefaultProfile(&access.ProfileConfig{
		AllowedNets:          cidrRangeToInternal(x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
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
	for _, p := range profiles {
		pbProfiles = append(pbProfiles, &Profile{
			Parental:     parentalToProtobuf(p.Parental),
			BlockingMode: blockingModeToProtobuf(p.BlockingMode),
			Access:       accessToProtobuf(p.Access.Config()),
			ProfileId:    string(p.ID),
			UpdateTime:   timestamppb.New(p.UpdateTime),
			DeviceIds:    unsafelyConvertStrSlice[agd.DeviceID, string](p.DeviceIDs),
			RuleListIds: unsafelyConvertStrSlice[agd.FilterListID, string](
				p.RuleListIDs,
			),
			CustomRules: unsafelyConvertStrSlice[agd.FilterRuleText, string](
				p.CustomRules,
			),
			FilteredResponseTtl: durationpb.New(p.FilteredResponseTTL),
			FilteringEnabled:    p.FilteringEnabled,
			SafeBrowsing:        safeBrowsingToProtobuf(p.SafeBrowsing),
			RuleListsEnabled:    p.RuleListsEnabled,
			QueryLogEnabled:     p.QueryLogEnabled,
			Deleted:             p.Deleted,
			BlockPrivateRelay:   p.BlockPrivateRelay,
			BlockFirefoxCanary:  p.BlockFirefoxCanary,
			IpLogEnabled:        p.IPLogEnabled,
			AutoDevicesEnabled:  p.AutoDevicesEnabled,
			RateLimit:           rateLimitToProtobuf(p.Ratelimiter.Config()),
		})
	}

	return pbProfiles
}

// accessToProtobuf converts access settings to protobuf structure.
func accessToProtobuf(c *access.ProfileConfig) (ac *AccessSettings) {
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

	return &AccessSettings{
		AllowlistCidr:        prefixesToProtobuf(c.AllowedNets),
		BlocklistCidr:        prefixesToProtobuf(c.BlockedNets),
		AllowlistAsn:         allowedASNs,
		BlocklistAsn:         blockedASNs,
		BlocklistDomainRules: c.BlocklistDomainRules,
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

// parentalToProtobuf converts parental settings to protobuf structure.
func parentalToProtobuf(s *agd.ParentalProtectionSettings) (pbSetts *ParentalProtectionSettings) {
	if s == nil {
		return nil
	}

	return &ParentalProtectionSettings{
		Schedule: scheduleToProtobuf(s.Schedule),
		BlockedServices: unsafelyConvertStrSlice[agd.BlockedServiceID, string](
			s.BlockedServices,
		),
		Enabled:           s.Enabled,
		BlockAdult:        s.BlockAdult,
		GeneralSafeSearch: s.GeneralSafeSearch,
		YoutubeSafeSearch: s.YoutubeSafeSearch,
	}
}

// parentalToProtobuf converts parental-settings schedule to protobuf structure.
func scheduleToProtobuf(s *agd.ParentalProtectionSchedule) (pbSched *ParentalProtectionSchedule) {
	if s == nil {
		return nil
	}

	return &ParentalProtectionSchedule{
		TimeZone: s.TimeZone.String(),
		Mon: &DayRange{
			Start: uint32(s.Week[time.Monday].Start),
			End:   uint32(s.Week[time.Monday].End),
		},
		Tue: &DayRange{
			Start: uint32(s.Week[time.Tuesday].Start),
			End:   uint32(s.Week[time.Tuesday].End),
		},
		Wed: &DayRange{
			Start: uint32(s.Week[time.Wednesday].Start),
			End:   uint32(s.Week[time.Wednesday].End),
		},
		Thu: &DayRange{
			Start: uint32(s.Week[time.Thursday].Start),
			End:   uint32(s.Week[time.Thursday].End),
		},
		Fri: &DayRange{
			Start: uint32(s.Week[time.Friday].Start),
			End:   uint32(s.Week[time.Friday].End),
		},
		Sat: &DayRange{
			Start: uint32(s.Week[time.Saturday].Start),
			End:   uint32(s.Week[time.Saturday].End),
		},
		Sun: &DayRange{
			Start: uint32(s.Week[time.Sunday].Start),
			End:   uint32(s.Week[time.Sunday].End),
		},
	}
}

// blockingModeToProtobuf converts a blocking-mode sum-type to a protobuf one.
func blockingModeToProtobuf(m dnsmsg.BlockingMode) (pbBlockingMode isProfile_BlockingMode) {
	switch m := m.(type) {
	case *dnsmsg.BlockingModeCustomIP:
		return &Profile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipsToByteSlices(m.IPv4),
				Ipv6: ipsToByteSlices(m.IPv6),
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

// ipToBytes is a wrapper around netip.Addr.MarshalBinary that ignores the
// always-nil error.
func ipToBytes(ip netip.Addr) (b []byte) {
	b, _ = ip.MarshalBinary()

	return b
}

// devicesToProtobuf converts a slice of devices to protobuf structures.
func devicesToProtobuf(devices []*agd.Device) (pbDevices []*Device) {
	pbDevices = make([]*Device, 0, len(devices))
	for _, d := range devices {
		pbDevices = append(pbDevices, &Device{
			Authentication:   authToProtobuf(d.Auth),
			DeviceId:         string(d.ID),
			LinkedIp:         ipToBytes(d.LinkedIP),
			HumanIdLower:     string(d.HumanIDLower),
			DeviceName:       string(d.Name),
			DedicatedIps:     ipsToByteSlices(d.DedicatedIPs),
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
	case agdpasswd.AllowAuthenticator:
		return nil
	case *agdpasswd.PasswordHashBcrypt:
		return &AuthenticationSettings_PasswordHashBcrypt{
			PasswordHashBcrypt: p.PasswordHash(),
		}
	default:
		panic(fmt.Errorf("bad password hash %T(%[1]v)", p))
	}
}

// ipsToByteSlices is a wrapper around netip.Addr.MarshalBinary that ignores the
// always-nil errors.
func ipsToByteSlices(ips []netip.Addr) (data [][]byte) {
	if ips == nil {
		return nil
	}

	data = make([][]byte, 0, len(ips))
	for _, ip := range ips {
		data = append(data, ipToBytes(ip))
	}

	return data
}

// safeBrowsingToProtobuf converts safe browsing settings to protobuf structure.
func safeBrowsingToProtobuf(s *agd.SafeBrowsingSettings) (sbSetts *SafeBrowsingSettings) {
	if s == nil {
		return nil
	}

	return &SafeBrowsingSettings{
		Enabled:                     s.Enabled,
		BlockDangerousDomains:       s.BlockDangerousDomains,
		BlockNewlyRegisteredDomains: s.BlockNewlyRegisteredDomains,
	}
}

// rateLimitToProtobuf converts rate limit settings to protobuf structure.
func rateLimitToProtobuf(c *agd.RatelimitConfig) (ac *RateLimitSettings) {
	if c == nil {
		return nil
	}

	return &RateLimitSettings{
		Enabled:    c.Enabled,
		Rps:        c.RPS,
		ClientCidr: prefixesToProtobuf(c.ClientSubnets),
	}
}
