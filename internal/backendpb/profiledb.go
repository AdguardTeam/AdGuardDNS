package backendpb

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdprotobuf"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProfileStorageConfig is the configuration for the business logic backend
// profile storage.
type ProfileStorageConfig struct {
	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl agd.ErrorCollector

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".
	Endpoint *url.URL
}

// ProfileStorage is the implementation of the [profiledb.Storage] interface
// that retrieves the profile and device information from the business logic
// backend.  It is safe for concurrent use.
type ProfileStorage struct {
	errColl agd.ErrorCollector

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
		return nil, fmt.Errorf("loading profiles: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, stream.CloseSend()) }()

	resp = &profiledb.StorageResponse{
		Profiles: []*agd.Profile{},
		Devices:  []*agd.Device{},
	}

	stats := &profilesCallStats{
		isFullSync: req.SyncTime == time.Time{},
	}

	for {
		stats.startRecv()
		profile, profErr := stream.Recv()
		if profErr != nil {
			if errors.Is(profErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf("receiving profile: %w", profErr)
		}
		stats.endRecv()

		stats.startDec()
		prof, devices, profErr := profile.toInternal(ctx, time.Now(), s.errColl)
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

// toInternal converts the protobuf-encoded data into a profile structure.
func (x *DNSProfile) toInternal(
	ctx context.Context,
	updTime time.Time,
	errColl agd.ErrorCollector,
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

	devices, deviceIds := devicesToInternal(ctx, x.Devices, errColl)
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
		RuleListsEnabled:    listsEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
		Deleted:             x.Deleted,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
	}, devices, nil
}

// toInternal converts a protobuf parental-settings structure to an internal
// one.  If x is nil, toInternal returns nil.
func (x *ParentalSettings) toInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
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

// blockedSvcsToInternal is a helper that converts the blocked service IDs from
// the backend response to AdGuard DNS blocked service IDs.
func blockedSvcsToInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
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

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.  If pbm is nil, blockingModeToInternal returns a null-IP
// blocking mode.
func blockingModeToInternal(pbm isDNSProfile_BlockingMode) (m dnsmsg.BlockingModeCodec, err error) {
	switch pbm := pbm.(type) {
	case nil:
		m.Mode = &dnsmsg.BlockingModeNullIP{}
	case *DNSProfile_BlockingModeCustomIp:
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
	case *DNSProfile_BlockingModeNxdomain:
		m.Mode = &dnsmsg.BlockingModeNXDOMAIN{}
	case *DNSProfile_BlockingModeNullIp:
		m.Mode = &dnsmsg.BlockingModeNullIP{}
	case *DNSProfile_BlockingModeRefused:
		m.Mode = &dnsmsg.BlockingModeREFUSED{}
	default:
		// Consider unhandled type-switch cases programmer errors.
		panic(fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm))
	}

	return m, nil
}

// devicesToInternal is a helper that converts the devices from protobuf to
// AdGuard DNS devices.
func devicesToInternal(
	ctx context.Context,
	ds []*DeviceSettings,
	errColl agd.ErrorCollector,
) (out []*agd.Device, ids []agd.DeviceID) {
	l := len(ds)
	if l == 0 {
		return nil, nil
	}

	out = make([]*agd.Device, 0, l)
	for _, d := range ds {
		dev, err := d.toInternal()
		if err != nil {
			reportf(ctx, errColl, "invalid device settings: %w", err)

			continue
		}

		ids = append(ids, dev.ID)
		out = append(out, dev)
	}

	return out, ids
}

// toInternal is a helper that converts device settings from backend protobuf
// response to AdGuard DNS device object.
func (ds *DeviceSettings) toInternal() (dev *agd.Device, err error) {
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

	id, err := agd.NewDeviceID(ds.Id)
	if err != nil {
		return nil, fmt.Errorf("device id: %s: %w", ds.Id, err)
	}

	name, err := agd.NewDeviceName(ds.Name)
	if err != nil {
		return nil, fmt.Errorf("device name: %s: %w", ds.Name, err)
	}

	return &agd.Device{
		ID:               id,
		Name:             name,
		LinkedIP:         linkedIP,
		DedicatedIPs:     dedicatedIPs,
		FilteringEnabled: ds.FilteringEnabled,
	}, nil
}

// rulesToInternal is a helper that converts the filter rules from the backend
// response to AdGuard DNS filtering rules.
func rulesToInternal(
	ctx context.Context,
	respRules []string,
	errColl agd.ErrorCollector,
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
	errColl agd.ErrorCollector,
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
