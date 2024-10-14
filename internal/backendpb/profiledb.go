package backendpb

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
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
	// BindSet is the subnet set created from DNS servers listening addresses.
	// It must not be nil.
	BindSet netutil.SubnetSet

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.  It must not be nil.
	ErrColl errcoll.Interface

	// Logger is used as the base logger for the profile storage.  It must not
	// be nil.
	Logger *slog.Logger

	// Metrics is used for the collection of the protobuf errors.
	Metrics Metrics

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

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
	bindSet     netutil.SubnetSet
	errColl     errcoll.Interface
	client      DNSServiceClient
	logger      *slog.Logger
	metrics     Metrics
	apiKey      string
	respSzEst   datasize.ByteSize
	maxProfSize datasize.ByteSize
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
		bindSet:     c.BindSet,
		errColl:     c.ErrColl,
		client:      client,
		logger:      c.Logger,
		metrics:     c.Metrics,
		apiKey:      c.APIKey,
		respSzEst:   c.ResponseSizeEstimate,
		maxProfSize: c.MaxProfilesSize,
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
		return nil, fmt.Errorf("calling backend: %w", fixGRPCError(ctx, s.metrics, err))
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
		return nil, fmt.Errorf("loading profiles: %w", fixGRPCError(ctx, s.metrics, err))
	}
	defer func() { err = errors.WithDeferred(err, stream.CloseSend()) }()

	resp = &profiledb.StorageProfilesResponse{
		Profiles: []*agd.Profile{},
		Devices:  []*agd.Device{},
	}

	stats := &profilesCallStats{
		logger:     s.logger,
		isFullSync: req.SyncTime.IsZero(),
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
				fixGRPCError(ctx, s.metrics, profErr),
			)
		}
		stats.endRecv()

		stats.startDec()
		prof, devices, profErr := profile.toInternal(
			ctx,
			time.Now(),
			s.bindSet,
			s.errColl,
			s.metrics,
			s.respSzEst,
		)
		if profErr != nil {
			reportf(ctx, s.errColl, "loading profile: %w", profErr)

			continue
		}
		stats.endDec()

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
