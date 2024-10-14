package backendpb

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/c2h5oh/datasize"
)

// toInternal converts the protobuf-encoded data into a profile structure and
// its device structures.
//
// TODO(a.garipov):  Refactor into a method of [*ProfileStorage]?
func (x *DNSProfile) toInternal(
	ctx context.Context,
	updTime time.Time,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	mtrc Metrics,
	respSzEst datasize.ByteSize,
) (profile *agd.Profile, devices []*agd.Device, err error) {
	if x == nil {
		return nil, nil, fmt.Errorf("profile is nil")
	}

	parental, err := x.Parental.toInternal(ctx, errColl)
	if err != nil {
		return nil, nil, fmt.Errorf("parental: %w", err)
	}

	m, err := blockingModeToInternal(x.BlockingMode)
	if err != nil {
		return nil, nil, fmt.Errorf("blocking mode: %w", err)
	}

	devices, deviceIds := devicesToInternal(ctx, x.Devices, bindSet, errColl, mtrc)
	listsEnabled, listIDs := x.RuleLists.toInternal(ctx, errColl)

	profID, err := agd.NewProfileID(x.DnsId)
	if err != nil {
		return nil, nil, fmt.Errorf("id: %w", err)
	}

	var fltRespTTL time.Duration
	if respTTL := x.FilteredResponseTtl; respTTL != nil {
		fltRespTTL = respTTL.AsDuration()
	}

	return &agd.Profile{
		Parental:            parental,
		BlockingMode:        m,
		ID:                  profID,
		UpdateTime:          updTime,
		DeviceIDs:           deviceIds,
		RuleListIDs:         listIDs,
		CustomRules:         rulesToInternal(ctx, x.CustomRules, errColl),
		FilteredResponseTTL: fltRespTTL,
		FilteringEnabled:    x.FilteringEnabled,
		Ratelimiter:         x.RateLimit.toInternal(ctx, errColl, respSzEst),
		SafeBrowsing:        x.SafeBrowsing.toInternal(),
		Access:              x.Access.toInternal(ctx, errColl),
		RuleListsEnabled:    listsEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
		Deleted:             x.Deleted,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
		IPLogEnabled:        x.IpLogEnabled,
		AutoDevicesEnabled:  x.AutoDevicesEnabled,
	}, devices, nil
}

// toInternal converts a protobuf parental-settings structure to an internal
// one.  If x is nil, toInternal returns nil.
func (x *ParentalSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
) (s *agd.ParentalProtectionSettings, err error) {
	if x == nil {
		return nil, nil
	}

	schedule, err := x.Schedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("schedule: %w", err)
	}

	return &agd.ParentalProtectionSettings{
		Schedule:          schedule,
		BlockedServices:   blockedSvcsToInternal(ctx, errColl, x.BlockedServices),
		Enabled:           x.Enabled,
		BlockAdult:        x.BlockAdult,
		GeneralSafeSearch: x.GeneralSafeSearch,
		YoutubeSafeSearch: x.YoutubeSafeSearch,
	}, nil
}

// toInternal converts protobuf rate-limiting settings to an internal structure.
// If x is nil, toInternal returns [agd.GlobalRatelimiter].
func (x *RateLimitSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	respSzEst datasize.ByteSize,
) (r agd.Ratelimiter) {
	if x == nil || !x.Enabled {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: cidrRangeToInternal(ctx, errColl, x.ClientCidr),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// toInternal converts protobuf safe-browsing settings to an internal structure.
// If x is nil, toInternal returns nil.
func (x *SafeBrowsingSettings) toInternal() (sb *agd.SafeBrowsingSettings) {
	if x == nil {
		return nil
	}

	return &agd.SafeBrowsingSettings{
		Enabled:                     x.Enabled,
		BlockDangerousDomains:       x.BlockDangerousDomains,
		BlockNewlyRegisteredDomains: x.BlockNrd,
	}
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].
func (x *AccessSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
) (a access.Profile) {
	if x == nil || !x.Enabled {
		return access.EmptyProfile{}
	}

	return access.NewDefaultProfile(&access.ProfileConfig{
		AllowedNets:          cidrRangeToInternal(ctx, errColl, x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(ctx, errColl, x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
	})
}

// cidrRangeToInternal is a helper that converts a slice of CidrRange to the
// slice of [netip.Prefix].
func cidrRangeToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	cidrs []*CidrRange,
) (out []netip.Prefix) {
	for i, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.Address)
		if !ok {
			reportf(ctx, errColl, "bad cidr at index %d: %v", i, c.Address)

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
// the backend response to AdGuard DNS blocked service IDs.
func blockedSvcsToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	respSvcs []string,
) (svcs []agd.BlockedServiceID) {
	l := len(respSvcs)
	if l == 0 {
		return nil
	}

	svcs = make([]agd.BlockedServiceID, 0, l)
	for i, s := range respSvcs {
		id, err := agd.NewBlockedServiceID(s)
		if err != nil {
			reportf(ctx, errColl, "blocked service at index %d: %w", i, err)

			continue
		}

		svcs = append(svcs, id)
	}

	return svcs
}

// toInternal converts a protobuf protection-schedule structure to an internal
// one.  If x is nil, toInternal returns nil.
func (x *ScheduleSettings) toInternal() (sch *agd.ParentalProtectionSchedule, err error) {
	if x == nil {
		return nil, nil
	}

	sch = &agd.ParentalProtectionSchedule{}

	sch.TimeZone, err = agdtime.LoadLocation(x.Tmz)
	if err != nil {
		return nil, fmt.Errorf("loading timezone: %w", err)
	}

	sch.Week = &agd.WeeklySchedule{}

	w := x.WeeklyRange
	days := []*DayRange{w.Sun, w.Mon, w.Tue, w.Wed, w.Thu, w.Fri, w.Sat}
	for i, d := range days {
		if d == nil {
			sch.Week[i] = agd.ZeroLengthDayRange()

			continue
		}

		sch.Week[i] = agd.DayRange{
			Start: uint16(d.Start.AsDuration().Minutes()),
			End:   uint16(d.End.AsDuration().Minutes()),
		}
	}

	for i, r := range sch.Week {
		err = r.Validate()
		if err != nil {
			return nil, fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}
	}

	return sch, nil
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

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.  If pbm is nil, blockingModeToInternal returns a null-IP
// blocking mode.
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
) (rules []agd.FilterRuleText) {
	l := len(respRules)
	if l == 0 {
		return nil
	}

	rules = make([]agd.FilterRuleText, 0, l)
	for i, r := range respRules {
		text, err := agd.NewFilterRuleText(r)
		if err != nil {
			reportf(ctx, errColl, "rule at index %d: %w", i, err)

			continue
		}

		rules = append(rules, text)
	}

	return rules
}

// toInternal is a helper that converts the filter lists from the backend
// response to AdGuard DNS filter list ids.  If x is nil, toInternal returns
// false and nil.
func (x *RuleListsSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
) (enabled bool, filterLists []agd.FilterListID) {
	if x == nil {
		return false, nil
	}

	l := len(x.Ids)
	if l == 0 {
		return x.Enabled, nil
	}

	filterLists = make([]agd.FilterListID, 0, l)
	for i, f := range x.Ids {
		id, err := agd.NewFilterListID(f)
		if err != nil {
			reportf(ctx, errColl, "filter id: at index %d: %w", i, err)

			continue
		}

		filterLists = append(filterLists, id)
	}

	return x.Enabled, filterLists
}
