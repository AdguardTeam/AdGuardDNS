package backendpb

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProfileStorageConfig is the configuration for the business logic backend
// profile storage.
type ProfileStorageConfig struct {
	// BindSet is the subnet set created from DNS servers listening addresses.
	BindSet netutil.SubnetSet

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl errcoll.Interface

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".
	Endpoint *url.URL
}

// ProfileStorage is the implementation of the [profiledb.Storage] interface
// that retrieves the profile and device information from the business logic
// backend.  It is safe for concurrent use.
type ProfileStorage struct {
	bindSet netutil.SubnetSet
	errColl errcoll.Interface

	// client is the current GRPC client.
	client DNSServiceClient
}

// NewProfileStorage returns a new [ProfileStorage] that retrieves information
// from the business logic backend.
func NewProfileStorage(c *ProfileStorageConfig) (s *ProfileStorage, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &ProfileStorage{
		bindSet: c.BindSet,
		client:  client,
		errColl: c.ErrColl,
	}, nil
}

// type check
var _ profiledb.Storage = (*ProfileStorage)(nil)

// Profiles implements the [profiledb.Storage] interface for *ProfileStorage.
func (s *ProfileStorage) Profiles(
	ctx context.Context,
	req *profiledb.StorageRequest,
) (resp *profiledb.StorageResponse, err error) {
	stream, err := s.client.GetDNSProfiles(ctx, toProtobuf(req))
	if err != nil {
		return nil, fmt.Errorf("loading profiles: %w", fixGRPCError(err))
	}
	defer func() { err = errors.WithDeferred(err, stream.CloseSend()) }()

	resp = &profiledb.StorageResponse{
		Profiles: []*agd.Profile{},
		Devices:  []*agd.Device{},
	}

	stats := &profilesCallStats{
		isFullSync: req.SyncTime.IsZero(),
	}

	for {
		stats.startRecv()
		profile, profErr := stream.Recv()
		if profErr != nil {
			if errors.Is(profErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf("receiving profile: %w", fixGRPCError(profErr))
		}
		stats.endRecv()

		stats.startDec()
		prof, devices, profErr := profile.toInternal(ctx, time.Now(), s.bindSet, s.errColl)
		if profErr != nil {
			reportf(ctx, s.errColl, "loading profile: %w", profErr)

			continue
		}
		stats.endDec()

		resp.Profiles = append(resp.Profiles, prof)
		resp.Devices = append(resp.Devices, devices...)
	}

	stats.report()

	trailer := stream.Trailer()
	resp.SyncTime, err = syncTimeFromTrailer(trailer)
	if err != nil {
		return nil, fmt.Errorf("retrieving sync_time: %w", err)
	}

	return resp, nil
}

// fixGRPCError wraps GRPC error if needed.  As the GRPC deadline error is not
// correctly wrapped, this helper detects it by the status code and replaces it
// with a simple DeadlineExceeded error.
//
// See https://github.com/grpc/grpc-go/issues/4822.
//
// TODO(d.kolyshev): Remove after the grpc-go issue is fixed.
func fixGRPCError(err error) (wErr error) {
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.DeadlineExceeded {
		err = fmt.Errorf("grpc: %w", context.DeadlineExceeded)
	}

	return err
}

// toInternal converts the protobuf-encoded data into a profile structure.
func (x *DNSProfile) toInternal(
	ctx context.Context,
	updTime time.Time,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
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

	devices, deviceIds := devicesToInternal(ctx, x.Devices, bindSet, errColl)
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
		SafeBrowsing:        x.SafeBrowsing.toInternal(),
		Access:              x.Access.toInternal(ctx, errColl),
		RuleListsEnabled:    listsEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
		Deleted:             x.Deleted,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
		IPLogEnabled:        x.IpLogEnabled,
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
			reportf(ctx, errColl, "invalid cidr at index %d: %w", i)

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

// devicesToInternal is a helper that converts the devices from protobuf to
// AdGuard DNS devices.
func devicesToInternal(
	ctx context.Context,
	ds []*DeviceSettings,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (out []*agd.Device, ids []agd.DeviceID) {
	l := len(ds)
	if l == 0 {
		return nil, nil
	}

	out = make([]*agd.Device, 0, l)
	for _, d := range ds {
		dev, err := d.toInternal(bindSet)
		if err != nil {
			reportf(ctx, errColl, "invalid device settings: %w", err)
			metrics.DevicesInvalidTotal.Inc()

			continue
		}

		ids = append(ids, dev.ID)
		out = append(out, dev)
	}

	return out, ids
}

// toInternal is a helper that converts device settings from backend protobuf
// response to AdGuard DNS device object.
func (ds *DeviceSettings) toInternal(bindSet netutil.SubnetSet) (dev *agd.Device, err error) {
	if ds == nil {
		return nil, fmt.Errorf("device is nil")
	}

	var linkedIP netip.Addr
	err = linkedIP.UnmarshalBinary(ds.LinkedIp)
	if err != nil {
		return nil, fmt.Errorf("linked ip: %w", err)
	}

	var dedicatedIPs []netip.Addr
	dedicatedIPs, err = agdprotobuf.ByteSlicesToIPs(ds.DedicatedIps)
	if err != nil {
		return nil, fmt.Errorf("dedicated ips: %w", err)
	}

	// TODO(d.kolyshev): Extract business logic validation.
	for _, addr := range dedicatedIPs {
		if !bindSet.Contains(addr) {
			return nil, fmt.Errorf("dedicated ip %q is not in bind data", addr)
		}
	}

	auth, err := ds.Authentication.toInternal()
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", ds.Id, err)
	}

	id, err := agd.NewDeviceID(ds.Id)
	if err != nil {
		return nil, fmt.Errorf("device id: %s: %w", ds.Id, err)
	}

	name, err := agd.NewDeviceName(ds.Name)
	if err != nil {
		return nil, fmt.Errorf("device name: %s: %w", ds.Name, err)
	}

	return &agd.Device{
		Auth:             auth,
		ID:               id,
		Name:             name,
		LinkedIP:         linkedIP,
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: ds.FilteringEnabled,
	}, nil
}

// toInternal converts a protobuf auth settings structure to an internal one.
// If x is nil, toInternal returns non-nil settings with enabled field set to
// false.
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
// internal one.
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
	for _, f := range x.Ids {
		id, err := agd.NewFilterListID(f)
		if err != nil {
			reportf(ctx, errColl, "invalid filter id: %s: %w", f, err)

			continue
		}

		filterLists = append(filterLists, id)
	}

	return x.Enabled, filterLists
}

// toProtobuf converts a storage request structure into the protobuf structure.
func toProtobuf(r *profiledb.StorageRequest) (req *DNSProfilesRequest) {
	return &DNSProfilesRequest{
		SyncTime: timestamppb.New(r.SyncTime),
	}
}

// syncTimeFromTrailer returns sync time from trailer metadata.  Trailer
// metadata must contain "sync_time" field with milliseconds presentation of
// sync time.
func syncTimeFromTrailer(trailer metadata.MD) (syncTime time.Time, err error) {
	st := trailer.Get("sync_time")
	if len(st) == 0 {
		return syncTime, fmt.Errorf("empty value")
	}

	syncTimeMs, err := strconv.ParseInt(st[0], 10, 64)
	if err != nil {
		return syncTime, fmt.Errorf("invalid value: %w", err)
	}

	return time.Unix(0, syncTimeMs*time.Millisecond.Nanoseconds()), nil
}
