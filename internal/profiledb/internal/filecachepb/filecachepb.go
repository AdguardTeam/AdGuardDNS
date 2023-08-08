// Package filecachepb contains the protobuf structures for the profile cache.
package filecachepb

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// toInternal converts the protobuf-encoded data into a cache structure.
func toInternal(fc *FileCache) (c *internal.FileCache, err error) {
	profiles, err := profilesToInternal(fc.Profiles)
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
func profilesToInternal(pbProfiles []*Profile) (profiles []*agd.Profile, err error) {
	profiles = make([]*agd.Profile, 0, len(pbProfiles))
	for i, pbProf := range pbProfiles {
		var prof *agd.Profile
		prof, err = pbProf.toInternal()
		if err != nil {
			return nil, fmt.Errorf("profile at index %d: %w", i, err)
		}

		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// toInternal converts a protobuf profile structure to an internal one.
func (x *Profile) toInternal() (prof *agd.Profile, err error) {
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
		BlockingMode: m,
		ID:           agd.ProfileID(x.ProfileId),
		UpdateTime:   x.UpdateTime.AsTime(),
		// Consider device IDs to have been prevalidated.
		DeviceIDs: unsafelyConvertStrSlice[string, agd.DeviceID](x.DeviceIds),
		// Consider rule-list IDs to have been prevalidated.
		RuleListIDs: unsafelyConvertStrSlice[string, agd.FilterListID](x.RuleListIds),
		// Consider rule-list IDs to have been prevalidated.
		CustomRules:         unsafelyConvertStrSlice[string, agd.FilterRuleText](x.CustomRules),
		FilteredResponseTTL: x.FilteredResponseTtl.AsDuration(),
		FilteringEnabled:    x.FilteringEnabled,
		SafeBrowsing:        x.SafeBrowsing.toInternal(),
		RuleListsEnabled:    x.RuleListsEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
		Deleted:             x.Deleted,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
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
			time.Monday:    {Start: uint16(x.Mon.Start), End: uint16(x.Mon.End)},
			time.Tuesday:   {Start: uint16(x.Tue.Start), End: uint16(x.Tue.End)},
			time.Wednesday: {Start: uint16(x.Wed.Start), End: uint16(x.Wed.End)},
			time.Thursday:  {Start: uint16(x.Thu.Start), End: uint16(x.Thu.End)},
			time.Friday:    {Start: uint16(x.Fri.Start), End: uint16(x.Fri.End)},
			time.Saturday:  {Start: uint16(x.Sat.Start), End: uint16(x.Sat.End)},
			time.Sunday:    {Start: uint16(x.Sun.Start), End: uint16(x.Sun.End)},
		},
		TimeZone: loc,
	}, nil
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.
func blockingModeToInternal(
	pbBlockingMode isProfile_BlockingMode,
) (m dnsmsg.BlockingModeCodec, err error) {
	switch pbm := pbBlockingMode.(type) {
	case *Profile_BlockingModeCustomIp:
		custom := &dnsmsg.BlockingModeCustomIP{}
		err = custom.IPv4.UnmarshalBinary(pbm.BlockingModeCustomIp.Ipv4)
		if err != nil {
			return dnsmsg.BlockingModeCodec{}, fmt.Errorf("bad custom ipv4: %w", err)
		}

		err = custom.IPv6.UnmarshalBinary(pbm.BlockingModeCustomIp.Ipv6)
		if err != nil {
			return dnsmsg.BlockingModeCodec{}, fmt.Errorf("bad custom ipv6: %w", err)
		}

		m.Mode = custom
	case *Profile_BlockingModeNxdomain:
		m.Mode = &dnsmsg.BlockingModeNXDOMAIN{}
	case *Profile_BlockingModeNullIp:
		m.Mode = &dnsmsg.BlockingModeNullIP{}
	case *Profile_BlockingModeRefused:
		m.Mode = &dnsmsg.BlockingModeREFUSED{}
	default:
		// Consider unhandled type-switch cases programmer errors.
		panic(fmt.Errorf("bad pb blocking mode %T(%[1]v)", m))
	}

	return m, nil
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
	dedicatedIPs, err = byteSlicesToIPs(x.DedicatedIps)
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	return &agd.Device{
		// Consider device IDs to have been prevalidated.
		ID:       agd.DeviceID(x.DeviceId),
		LinkedIP: linkedIP,
		// Consider device names to have been prevalidated.
		Name:             agd.DeviceName(x.DeviceName),
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: x.FilteringEnabled,
	}, nil
}

// byteSlicesToIPs converts a slice of byte slices into a slice of netip.Addrs.
func byteSlicesToIPs(data [][]byte) (ips []netip.Addr, err error) {
	if data == nil {
		return nil, nil
	}

	ips = make([]netip.Addr, 0, len(data))
	for i, ipData := range data {
		var ip netip.Addr
		err = ip.UnmarshalBinary(ipData)
		if err != nil {
			return nil, fmt.Errorf("ip at index %d: %w", i, err)
		}

		ips = append(ips, ip)
	}

	return ips, nil
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

// profilesToProtobuf converts a slice of profiles to protobuf structures.
func profilesToProtobuf(profiles []*agd.Profile) (pbProfiles []*Profile) {
	pbProfiles = make([]*Profile, 0, len(profiles))
	for _, p := range profiles {
		pbProfiles = append(pbProfiles, &Profile{
			Parental:            parentalToProtobuf(p.Parental),
			BlockingMode:        blockingModeToProtobuf(p.BlockingMode),
			ProfileId:           string(p.ID),
			UpdateTime:          timestamppb.New(p.UpdateTime),
			DeviceIds:           unsafelyConvertStrSlice[agd.DeviceID, string](p.DeviceIDs),
			RuleListIds:         unsafelyConvertStrSlice[agd.FilterListID, string](p.RuleListIDs),
			CustomRules:         unsafelyConvertStrSlice[agd.FilterRuleText, string](p.CustomRules),
			FilteredResponseTtl: durationpb.New(p.FilteredResponseTTL),
			FilteringEnabled:    p.FilteringEnabled,
			SafeBrowsing:        safeBrowsingToProtobuf(p.SafeBrowsing),
			RuleListsEnabled:    p.RuleListsEnabled,
			QueryLogEnabled:     p.QueryLogEnabled,
			Deleted:             p.Deleted,
			BlockPrivateRelay:   p.BlockPrivateRelay,
			BlockFirefoxCanary:  p.BlockFirefoxCanary,
		})
	}

	return pbProfiles
}

// parentalToProtobuf converts parental settings to protobuf structure.
func parentalToProtobuf(s *agd.ParentalProtectionSettings) (pbSetts *ParentalProtectionSettings) {
	if s == nil {
		return nil
	}

	return &ParentalProtectionSettings{
		Schedule:          scheduleToProtobuf(s.Schedule),
		BlockedServices:   unsafelyConvertStrSlice[agd.BlockedServiceID, string](s.BlockedServices),
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
func blockingModeToProtobuf(m dnsmsg.BlockingModeCodec) (pbBlockingMode isProfile_BlockingMode) {
	switch m := m.Mode.(type) {
	case *dnsmsg.BlockingModeCustomIP:
		return &Profile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipToBytes(m.IPv4),
				Ipv6: ipToBytes(m.IPv6),
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
			DeviceId:         string(d.ID),
			LinkedIp:         ipToBytes(d.LinkedIP),
			DeviceName:       string(d.Name),
			DedicatedIps:     ipsToByteSlices(d.DedicatedIPs),
			FilteringEnabled: d.FilteringEnabled,
		})
	}

	return pbDevices
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
