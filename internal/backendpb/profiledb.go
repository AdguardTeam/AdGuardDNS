package backendpb

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"google.golang.org/grpc/metadata"
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

	// APIKey is the API key used for authentication, if any.
	APIKey string
}

// ProfileStorage is the implementation of the [profiledb.Storage] interface
// that retrieves the profile and device information from the business logic
// backend.  It is safe for concurrent use.
type ProfileStorage struct {
	bindSet netutil.SubnetSet
	errColl errcoll.Interface
	client  DNSServiceClient
	apiKey  string
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
		errColl: c.ErrColl,
		client:  client,
		apiKey:  c.APIKey,
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
		return nil, fmt.Errorf("calling backend: %w", fixGRPCError(err))
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
	stream, err := s.client.GetDNSProfiles(ctx, toProtobuf(req))
	if err != nil {
		return nil, fmt.Errorf("loading profiles: %w", fixGRPCError(err))
	}
	defer func() { err = errors.WithDeferred(err, stream.CloseSend()) }()

	resp = &profiledb.StorageProfilesResponse{
		Profiles: []*agd.Profile{},
		Devices:  []*agd.Device{},
	}

	stats := &profilesCallStats{
		isFullSync: req.SyncTime.IsZero(),
	}

	for n := 1; ; n++ {
		stats.startRecv()
		profile, profErr := stream.Recv()
		if profErr != nil {
			if errors.Is(profErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf("receiving profile #%d: %w", n, fixGRPCError(profErr))
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
