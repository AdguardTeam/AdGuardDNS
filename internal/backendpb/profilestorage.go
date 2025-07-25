package backendpb

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/c2h5oh/datasize"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProfileStorageConfig is the configuration for the business logic backend
// profile storage.
type ProfileStorageConfig struct {
	// Logger is used for logging the operation of the profile storage.  It must
	// not be nil.
	Logger *slog.Logger

	// BaseCustomLogger is the base logger used for the custom filters.
	BaseCustomLogger *slog.Logger

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

	// ProfileAccessConstructor is used to create access managers for profiles.
	// It must not be nil.
	ProfileAccessConstructor *access.ProfileConstructor

	// BindSet is the subnet set created from DNS servers listening addresses.
	// It must not be nil.
	BindSet netutil.SubnetSet

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.  It must not be nil.
	ErrColl errcoll.Interface

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Metrics is used for the collection of the profiles storage statistics.
	Metrics ProfileDBMetrics

	// APIKey is the API key used for authentication, if any.  If empty, no
	// authentication is performed.
	APIKey string

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of custom ratelimiting.  Responses over this estimate are
	// counted as several responses.
	ResponseSizeEstimate datasize.ByteSize

	// MaxProfilesSize is the maximum response size for the profiles endpoint.
	MaxProfilesSize datasize.ByteSize
}

// ProfileStorage is the implementation of the [profiledb.Storage] interface
// that retrieves the profile and device information from the business logic
// backend.  It is safe for concurrent use.
type ProfileStorage struct {
	logger           *slog.Logger
	baseCustomLogger *slog.Logger
	profAccessCons   *access.ProfileConstructor
	bindSet          netutil.SubnetSet
	errColl          errcoll.Interface
	client           DNSServiceClient
	grpcMetrics      GRPCMetrics
	metrics          ProfileDBMetrics
	apiKey           string
	respSzEst        datasize.ByteSize
	maxProfSize      datasize.ByteSize
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
		logger:           c.Logger,
		baseCustomLogger: c.BaseCustomLogger,
		profAccessCons:   c.ProfileAccessConstructor,
		bindSet:          c.BindSet,
		errColl:          c.ErrColl,
		client:           NewDNSServiceClient(client),
		grpcMetrics:      c.GRPCMetrics,
		metrics:          c.Metrics,
		apiKey:           c.APIKey,
		respSzEst:        c.ResponseSizeEstimate,
		maxProfSize:      c.MaxProfilesSize,
	}, nil
}

// type check
var _ profiledb.Storage = (*ProfileStorage)(nil)

// CreateAutoDevice implements the [profile.Storage] interface for
// *ProfileStorage.
func (s *ProfileStorage) CreateAutoDevice(
	ctx context.Context,
	req *profiledb.StorageCreateAutoDeviceRequest,
) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
	defer func() {
		err = errors.Annotate(
			err,
			"creating auto device for profile %q and human id %q: %w",
			req.ProfileID,
			req.HumanID,
		)
	}()

	ctx = ctxWithAuthentication(ctx, s.apiKey)
	backendResp, err := s.client.CreateDeviceByHumanId(ctx, &CreateDeviceRequest{
		DnsId:      string(req.ProfileID),
		HumanId:    string(req.HumanID),
		DeviceType: DeviceType(req.DeviceType),
	})
	if err != nil {
		return nil, fmt.Errorf("calling backend: %w", fixGRPCError(ctx, s.grpcMetrics, err))
	}

	d, err := backendResp.Device.toInternal(s.bindSet)
	if err != nil {
		return nil, fmt.Errorf("converting device: %w", err)
	}

	return &profiledb.StorageCreateAutoDeviceResponse{
		Device: d,
	}, nil
}

// Profiles implements the [profiledb.Storage] interface for *ProfileStorage.
func (s *ProfileStorage) Profiles(
	ctx context.Context,
	req *profiledb.StorageProfilesRequest,
) (resp *profiledb.StorageProfilesResponse, err error) {
	ctx = ctxWithAuthentication(ctx, s.apiKey)

	// #nosec G115 -- The value of limit comes from validated environment
	// variables.
	respSzOpt := grpc.MaxCallRecvMsgSize(int(s.maxProfSize.Bytes()))
	stream, err := s.client.GetDNSProfiles(ctx, toProtobuf(req), respSzOpt)
	if err != nil {
		return nil, fmt.Errorf("loading profiles: %w", fixGRPCError(ctx, s.grpcMetrics, err))
	}
	defer func() { err = errors.WithDeferred(err, stream.CloseSend()) }()

	resp = &profiledb.StorageProfilesResponse{
		DeviceChanges: map[agd.ProfileID]*profiledb.StorageDeviceChange{},
		Profiles:      []*agd.Profile{},
		Devices:       []*agd.Device{},
	}

	isFullSync := req.SyncTime.IsZero()
	stats := &profilesCallStats{
		logger:     s.logger,
		isFullSync: isFullSync,
	}

	for n := 1; ; n++ {
		stats.startRecv()
		profile, profErr := stream.Recv()
		if profErr != nil {
			if errors.Is(profErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf(
				"receiving profile #%d: %w",
				n,
				fixGRPCError(ctx, s.grpcMetrics, profErr),
			)
		}
		stats.endRecv()

		stats.startDec()
		prof, devices, devChg, profErr := s.newProfile(ctx, profile, isFullSync)
		if profErr != nil {
			errcoll.Collect(ctx, s.errColl, s.logger, "loading profile", profErr)

			continue
		}
		stats.endDec()

		resp.DeviceChanges[prof.ID] = devChg
		resp.Profiles = append(resp.Profiles, prof)
		resp.Devices = append(resp.Devices, devices...)
	}

	stats.report(ctx, s.metrics)

	trailer := stream.Trailer()
	resp.SyncTime, err = syncTimeFromTrailer(trailer)
	if err != nil {
		return nil, fmt.Errorf("retrieving sync_time: %w", err)
	}

	return resp, nil
}

// newProfile returns a new profile structure and device structures created from
// the protobuf-encoded data.
func (s *ProfileStorage) newProfile(
	ctx context.Context,
	p *DNSProfile,
	isFullSync bool,
) (profile *agd.Profile, devices []*agd.Device, devChg *profiledb.StorageDeviceChange, err error) {
	if p == nil {
		return nil, nil, nil, errors.ErrNoValue
	}

	parental, err := p.Parental.toInternal(ctx, s.errColl, s.logger)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parental: %w", err)
	}

	m, err := blockingModeToInternal(p.BlockingMode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("blocking mode: %w", err)
	}

	devChg = &profiledb.StorageDeviceChange{}
	var deviceIDs []agd.DeviceID
	if l := len(p.Devices); l != 0 {
		optslog.Trace2(ctx, s.logger, "got devices", "profile_id", p.DnsId, "len", l)

		devices, deviceIDs = devicesToInternal(
			ctx,
			p.Devices,
			s.bindSet,
			s.errColl,
			s.logger,
			s.metrics,
		)
	} else if l = len(p.DeviceChanges); l != 0 {
		optslog.Trace2(ctx, s.logger, "got device changes", "profile_id", p.DnsId, "len", l)

		devChg.IsPartial = true
		devices, deviceIDs, devChg.DeletedDeviceIDs = deviceChangesToInternal(
			ctx,
			p.DeviceChanges,
			s.bindSet,
			s.errColl,
			s.logger,
			s.metrics,
		)
	} else {
		// If the sync is full, the absence of devices shows that a profile has
		// no devices, however in a partial sync it shows the absence of changes
		// in the devices.
		devChg.IsPartial = !isFullSync
	}

	profID, err := agd.NewProfileID(p.DnsId)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("id: %w", err)
	}

	accID, err := agd.NewAccountID(p.AccountId)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("account id: %w", err)
	}

	var fltRespTTL time.Duration
	if respTTL := p.FilteredResponseTtl; respTTL != nil {
		fltRespTTL = respTTL.AsDuration()
	}

	customRules := rulesToInternal(ctx, p.CustomRules, s.errColl, s.logger)
	customEnabled := len(customRules) > 0

	var customFilter filter.Custom
	if customEnabled {
		customFilter = custom.New(&custom.Config{
			Logger: s.baseCustomLogger.With("client_id", string(profID)),
			Rules:  customRules,
		})
	}

	customConf := &filter.ConfigCustom{
		Filter: customFilter,
		// TODO(a.garipov):  Consider adding an explicit flag to the protocol.
		Enabled: customEnabled,
	}

	return &agd.Profile{
		CustomDomains: p.CustomDomain.toInternal(ctx, s.errColl, s.logger),
		DeviceIDs:     container.NewMapSet(deviceIDs...),
		FilterConfig: &filter.ConfigClient{
			Custom:       customConf,
			Parental:     parental,
			RuleList:     p.RuleLists.toInternal(ctx, s.errColl, s.logger),
			SafeBrowsing: p.SafeBrowsing.toInternal(),
		},
		Access:              p.Access.toInternal(ctx, s.logger, s.errColl, s.profAccessCons),
		BlockingMode:        m,
		Ratelimiter:         p.RateLimit.toInternal(ctx, s.errColl, s.logger, s.respSzEst),
		AccountID:           accID,
		ID:                  profID,
		FilteredResponseTTL: fltRespTTL,
		AutoDevicesEnabled:  p.AutoDevicesEnabled,
		BlockChromePrefetch: p.BlockChromePrefetch,
		BlockFirefoxCanary:  p.BlockFirefoxCanary,
		BlockPrivateRelay:   p.BlockPrivateRelay,
		Deleted:             p.Deleted,
		FilteringEnabled:    p.FilteringEnabled,
		IPLogEnabled:        p.IpLogEnabled,
		QueryLogEnabled:     p.QueryLogEnabled,
	}, devices, devChg, nil
}

// toProtobuf converts a storage request structure into the protobuf structure.
func toProtobuf(r *profiledb.StorageProfilesRequest) (req *DNSProfilesRequest) {
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
		return syncTime, fmt.Errorf("bad value: %w", err)
	}

	return time.Unix(0, syncTimeMs*time.Millisecond.Nanoseconds()), nil
}
