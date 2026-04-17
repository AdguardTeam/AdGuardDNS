package backendgrpc

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
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
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

	// MaxInvalidRatio is the maximum allowed ratio of invalid profiles in a
	// response.  If the number of invalid profiles is greater than or equal to
	// the total number of profiles multiplied by this value, the whole response
	// is rejected.  The value must be in the range [0, 1].
	MaxInvalidRatio float64
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
	client           dnspb.DNSServiceClient
	grpcMetrics      GRPCMetrics
	metrics          ProfileDBMetrics
	apiKey           string
	respSzEst        datasize.ByteSize
	maxProfSize      datasize.ByteSize
	maxInvalidRatio  float64
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
		client:           dnspb.NewDNSServiceClient(client),
		grpcMetrics:      c.GRPCMetrics,
		metrics:          c.Metrics,
		apiKey:           c.APIKey,
		respSzEst:        c.ResponseSizeEstimate,
		maxProfSize:      c.MaxProfilesSize,
		maxInvalidRatio:  c.MaxInvalidRatio,
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
	backendResp, err := s.client.CreateDeviceByHumanId(ctx, &dnspb.CreateDeviceRequest{
		DnsId:      string(req.ProfileID),
		HumanId:    string(req.HumanID),
		DeviceType: dnspb.DeviceType(req.DeviceType),
	})
	if err != nil {
		return nil, fmt.Errorf("calling backend: %w", fixGRPCError(ctx, s.grpcMetrics, err))
	}

	d, err := backendResp.Device.ToInternal(s.bindSet)
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

	return s.readProfilesFromStream(ctx, stream, req.SyncTime.IsZero())
}

// readProfilesFromStream reads all DNS profiles from the stream and returns the
// assembled response.  stream must not be nil.
func (s *ProfileStorage) readProfilesFromStream(
	ctx context.Context,
	stream grpc.ServerStreamingClient[dnspb.DNSProfile],
	isFullSync bool,
) (resp *profiledb.StorageProfilesResponse, err error) {
	resp = &profiledb.StorageProfilesResponse{
		DeviceChanges: map[agd.ProfileID]*profiledb.StorageDeviceChange{},
		Profiles:      []*agd.Profile{},
		Devices:       []*agd.Device{},
	}

	stats := &profilesCallStats{
		logger:     s.logger,
		isFullSync: isFullSync,
	}

	for n := 1; ; n++ {
		var p *dnspb.DNSProfile

		stats.startRecv()
		p, err = stream.Recv()
		stats.endRecv()

		if err == nil {
			s.addProfileToResp(ctx, p, resp, stats, isFullSync)

			continue
		} else if errors.Is(err, io.EOF) {
			break
		}

		err = fixGRPCError(ctx, s.grpcMetrics, err)

		return nil, fmt.Errorf("receiving profile #%d: %w", n, err)
	}

	stats.report(ctx, s.metrics)

	err = s.checkBadProfilesRatio(stats.numBad, uint(len(resp.Profiles)))
	if err != nil {
		// Do not wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp.SyncTime, err = syncTimeFromTrailer(stream.Trailer())
	if err != nil {
		return nil, fmt.Errorf("retrieving sync_time: %w", err)
	}

	return resp, nil
}

// checkBadProfilesRatio returns an error if the ratio of bad profiles to total
// profiles is not allowed by the storage maximum invalid ratio.
func (s *ProfileStorage) checkBadProfilesRatio(numBad, numGood uint) (err error) {
	if numBad == 0 {
		return nil
	}

	total := numBad + numGood
	if float64(numBad) > float64(total)*s.maxInvalidRatio {
		return fmt.Errorf("too many invalid profiles: %d out of %d", numBad, total)
	}

	return nil
}

// addProfileToResp converts p into AdGuard DNS internal structures and stores
// its data in resp.  p, resp, and stats must not be nil.
func (s *ProfileStorage) addProfileToResp(
	ctx context.Context,
	p *dnspb.DNSProfile,
	resp *profiledb.StorageProfilesResponse,
	stats *profilesCallStats,
	isFullSync bool,
) {
	stats.startDec()
	res, err := p.ToInternal(
		ctx,
		s.logger,
		s.baseCustomLogger,
		s.profAccessCons,
		s.bindSet,
		s.errColl,
		s.maxProfSize,
		isFullSync,
	)
	stats.endDec()

	defer s.metrics.IncrementInvalidDevicesCount(ctx, res.NumBadDevice)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "loading profile", err)
		stats.incBadProf()

		return
	}

	resp.DeviceChanges[res.Profile.ID] = res.DeviceChange
	resp.Profiles = append(resp.Profiles, res.Profile)
	resp.Devices = append(resp.Devices, res.Devices...)
}

// toProtobuf converts a storage request structure into the protobuf structure.
func toProtobuf(r *profiledb.StorageProfilesRequest) (req *dnspb.DNSProfilesRequest) {
	return &dnspb.DNSProfilesRequest{
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
