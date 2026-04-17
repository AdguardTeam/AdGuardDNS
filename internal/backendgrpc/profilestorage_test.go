package backendgrpc_test

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// testDevType is a device type for tests.
	testDevType = agd.DeviceTypeOther

	// badDNSProfileID is a profile DNS ID that is longer than the allowed maximum,
	// causing ToInternal to fail.
	badDNSProfileID = "toolong123"
)

func TestProfileStorage_CreateAutoDevice(t *testing.T) {
	t.Parallel()

	gotReqCh := make(chan *dnspb.CreateDeviceRequest, 1)
	respCh := make(chan *dnspb.CreateDeviceResponse, 1)
	errCh := make(chan error, 1)

	srv := newTestDNSServer(t, nil, nil, newTestOnCreateDevice(t, gotReqCh, respCh, errCh))

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterDNSServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	s := newTestProfileStorage(t, endpoint)

	require.True(t, t.Run("success", func(t *testing.T) {
		ds := &dnspb.DeviceSettings{
			Id:           backendtest.DeviceIDStr,
			HumanIdLower: backendtest.HumanIDLowerStr,
		}

		wantResp := &dnspb.CreateDeviceResponse{
			Device: ds,
		}

		testutil.RequireSend(t, respCh, wantResp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		resp, err := s.CreateAutoDevice(ctx, &profiledb.StorageCreateAutoDeviceRequest{
			ProfileID:  backendtest.ProfileID,
			HumanID:    backendtest.HumanID,
			DeviceType: testDevType,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Device)

		gotReq, ok := testutil.RequireReceive(t, gotReqCh, backendtest.Timeout)
		require.True(t, ok)
		require.NotNil(t, gotReq)

		wantReq := &dnspb.CreateDeviceRequest{
			DnsId:      backendtest.ProfileIDStr,
			HumanId:    backendtest.HumanIDStr,
			DeviceType: dnspb.DeviceType(testDevType),
		}

		assert.EqualExportedValues(t, wantReq, gotReq)
		assert.Equal(t, backendtest.DeviceID, resp.Device.ID)
		assert.Equal(t, backendtest.HumanIDLower, resp.Device.HumanIDLower)
	}))

	require.True(t, t.Run("grpc_error", func(t *testing.T) {
		const wantErrMsg = `creating auto device for profile "` + backendtest.ProfileIDStr +
			`" and human id "` + backendtest.HumanIDStr + `": calling backend: rpc error: code = ` +
			`Unknown desc = assert.AnError general error for testing`

		testutil.RequireSend(t, respCh, nil, backendtest.Timeout)
		testutil.RequireSend(t, errCh, assert.AnError, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		resp, err := s.CreateAutoDevice(ctx, &profiledb.StorageCreateAutoDeviceRequest{
			ProfileID:  backendtest.ProfileID,
			HumanID:    backendtest.HumanID,
			DeviceType: testDevType,
		})
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, resp)

		gotReq, ok := testutil.RequireReceive(t, gotReqCh, backendtest.Timeout)
		require.True(t, ok)
		require.NotNil(t, gotReq)
	}))
}

func TestProfileStorage_CreateAutoDevice_deviceErrors(t *testing.T) {
	t.Parallel()

	gotReqCh := make(chan *dnspb.CreateDeviceRequest, 1)
	respCh := make(chan *dnspb.CreateDeviceResponse, 1)
	errCh := make(chan error, 1)

	srv := newTestDNSServer(t, nil, nil, newTestOnCreateDevice(t, gotReqCh, respCh, errCh))

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterDNSServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	s := newTestProfileStorage(t, endpoint)

	require.True(t, t.Run("invalid_device_id", func(t *testing.T) {
		const wantErrMsg = `creating auto device for profile "` + backendtest.ProfileIDStr +
			`" and human id "` + backendtest.HumanIDStr + `": converting device: device id: ` +
			`bad device id "": too short: got 0 bytes, min 1`

		ds := &dnspb.DeviceSettings{
			HumanIdLower: backendtest.HumanIDLowerStr,
		}

		wantResp := &dnspb.CreateDeviceResponse{
			Device: ds,
		}

		testutil.RequireSend(t, respCh, wantResp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		resp, err := s.CreateAutoDevice(ctx, &profiledb.StorageCreateAutoDeviceRequest{
			ProfileID:  backendtest.ProfileID,
			HumanID:    backendtest.HumanID,
			DeviceType: testDevType,
		})

		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, resp)

		gotReq, ok := testutil.RequireReceive(t, gotReqCh, backendtest.Timeout)
		require.True(t, ok)
		require.NotNil(t, gotReq)
	}))

	require.True(t, t.Run("invalid_device_human_id", func(t *testing.T) {
		humanIDLower := "ABC"

		wantErrMsg := `creating auto device for profile "` + backendtest.ProfileIDStr +
			`" and human id "` + backendtest.HumanIDStr + `": converting device: lowercase human ` +
			`id: bad lowercase human id "` + humanIDLower + `": at index 0: 'A' is not lowercase`

		ds := &dnspb.DeviceSettings{
			Id:           backendtest.DeviceIDStr,
			HumanIdLower: humanIDLower,
		}

		wantResp := &dnspb.CreateDeviceResponse{
			Device: ds,
		}

		testutil.RequireSend(t, respCh, wantResp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		resp, err := s.CreateAutoDevice(ctx, &profiledb.StorageCreateAutoDeviceRequest{
			ProfileID:  backendtest.ProfileID,
			HumanID:    backendtest.HumanID,
			DeviceType: testDevType,
		})

		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, resp)

		gotReq, ok := testutil.RequireReceive(t, gotReqCh, backendtest.Timeout)
		require.True(t, ok)
		require.NotNil(t, gotReq)
	}))
}

func TestProfileStorage_Profiles(t *testing.T) {
	t.Parallel()

	syncTime := strconv.FormatInt(backendtest.TimeSync.UnixMilli(), 10)
	srvProf := backendtest.NewDNSProfile(t)
	errCh := make(chan error, 1)
	trailerCh := make(chan metadata.MD, 1)

	srv := newTestDNSServer(t, newTestOnGetDNSProfiles(t, srvProf, trailerCh, errCh), nil, nil)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterDNSServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	s := newTestProfileStorage(t, endpoint)

	profileRes, err := srvProf.ToInternal(
		testutil.ContextWithTimeout(t, backendtest.Timeout),
		backendtest.Logger,
		backendtest.Logger,
		backendtest.ProfileAccessConstructor,
		backendtest.Bind,
		backendtest.ErrColl,
		backendtest.ResponseSizeEstimate,
		true,
	)
	require.NoError(t, err)
	require.NotNil(t, profileRes)

	okStorageProfiles := &profiledb.StorageProfilesResponse{
		SyncTime: backendtest.TimeSync,
		Profiles: []*agd.Profile{
			profileRes.Profile,
		},
		Devices: profileRes.Devices,
		DeviceChanges: map[agd.ProfileID]*profiledb.StorageDeviceChange{
			backendtest.ProfileIDStr: profileRes.DeviceChange,
		},
	}

	require.True(t, t.Run("success", func(t *testing.T) {
		trailerMD := metadata.MD{"sync_time": []string{syncTime}}
		testutil.RequireSend(t, trailerCh, trailerMD, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		req := &profiledb.StorageProfilesRequest{
			SyncTime: backendtest.TimeSync,
		}

		var storageProfiles *profiledb.StorageProfilesResponse
		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		storageProfiles, err = s.Profiles(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, storageProfiles)

		storageProfiles.SyncTime = storageProfiles.SyncTime.UTC()
		agdtest.AssertEqualProfile(t, okStorageProfiles.Profiles, storageProfiles.Profiles)

		assert.Equal(t, okStorageProfiles.Devices, storageProfiles.Devices)
		assert.Equal(t, okStorageProfiles.DeviceChanges, storageProfiles.DeviceChanges)
	}))

	require.True(t, t.Run("invalid_sync_time", func(t *testing.T) {
		invalidSyncTime := "abcd"

		wantErrMsg := `retrieving sync_time: bad value: strconv.ParseInt: parsing "` +
			invalidSyncTime + `": invalid syntax`

		trailerMD := metadata.MD{"sync_time": []string{invalidSyncTime}}
		testutil.RequireSend(t, trailerCh, trailerMD, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		req := &profiledb.StorageProfilesRequest{
			SyncTime: backendtest.TimeSync,
		}

		var storageProfiles *profiledb.StorageProfilesResponse
		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		storageProfiles, err = s.Profiles(ctx, req)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, storageProfiles)
	}))

	require.True(t, t.Run("grpc_error", func(t *testing.T) {
		const wantErrMsg = "receiving profile #2: rpc error: code = Unknown desc = " +
			"assert.AnError general error for testing"

		testutil.RequireSend(t, trailerCh, nil, backendtest.Timeout)
		testutil.RequireSend(t, errCh, assert.AnError, backendtest.Timeout)

		req := &profiledb.StorageProfilesRequest{
			SyncTime: backendtest.TimeSync,
		}

		var storageProfiles *profiledb.StorageProfilesResponse
		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		storageProfiles, err = s.Profiles(ctx, req)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, storageProfiles)
	}))
}

func TestProfileStorage_Profiles_maxInvalidRatio(t *testing.T) {
	t.Parallel()

	validProf := backendtest.NewDNSProfile(t)
	badProf := &dnspb.DNSProfile{DnsId: badDNSProfileID}

	testCases := []struct {
		name            string
		wantErrMsg      string
		profiles        []*dnspb.DNSProfile
		ratio           float64
		wantProfErrsNum int
	}{{
		name:            "below_ratio",
		wantErrMsg:      "",
		profiles:        []*dnspb.DNSProfile{validProf, validProf, validProf, badProf},
		ratio:           0.5,
		wantProfErrsNum: 1,
	}, {
		name:            "at_ratio",
		wantErrMsg:      "",
		profiles:        []*dnspb.DNSProfile{validProf, validProf, badProf, badProf},
		ratio:           0.5,
		wantProfErrsNum: 2,
	}, {
		name:            "above_ratio",
		wantErrMsg:      "too many invalid profiles: 3 out of 4",
		profiles:        []*dnspb.DNSProfile{validProf, badProf, badProf, badProf},
		ratio:           0.5,
		wantProfErrsNum: 3,
	}, {
		name:            "no_invalid_profiles",
		wantErrMsg:      "",
		profiles:        []*dnspb.DNSProfile{validProf, validProf},
		ratio:           0,
		wantProfErrsNum: 0,
	}, {
		name:            "all_invalid_profiles",
		wantErrMsg:      "too many invalid profiles: 2 out of 2",
		profiles:        []*dnspb.DNSProfile{badProf, badProf},
		ratio:           0,
		wantProfErrsNum: 2,
	}, {
		name:            "all_invalid_ratio_allowed",
		wantErrMsg:      "",
		profiles:        []*dnspb.DNSProfile{badProf, badProf},
		ratio:           1,
		wantProfErrsNum: 2,
	}, {
		name:            "one_invalid_ratio_allowed",
		wantErrMsg:      "",
		profiles:        []*dnspb.DNSProfile{validProf, badProf},
		ratio:           1,
		wantProfErrsNum: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newTestDNSServiceServer(t, tc.profiles)

			grpcSrv := grpc.NewServer(
				grpc.ConnectionTimeout(backendtest.Timeout),
				grpc.Creds(insecure.NewCredentials()),
			)
			dnspb.RegisterDNSServiceServer(grpcSrv, srv)
			endpoint := runLocalGRPCServer(t, grpcSrv)

			profErrsCount := 0
			errColl := &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { profErrsCount++ },
			}

			s, err := backendgrpc.NewProfileStorage(&backendgrpc.ProfileStorageConfig{
				Logger:                   backendtest.Logger,
				BaseCustomLogger:         backendtest.Logger,
				Endpoint:                 endpoint,
				ProfileAccessConstructor: backendtest.ProfileAccessConstructor,
				BindSet:                  backendtest.Bind,
				ErrColl:                  errColl,
				GRPCMetrics:              backendgrpc.EmptyGRPCMetrics{},
				Metrics:                  backendgrpc.EmptyProfileDBMetrics{},
				MaxProfilesSize:          1 * datasize.MB,
				MaxInvalidRatio:          tc.ratio,
			})
			require.NoError(t, err)

			ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
			_, err = s.Profiles(ctx, &profiledb.StorageProfilesRequest{})
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProfErrsNum, profErrsCount)
		})
	}
}

// newTestDNSServiceServer is a helper that returns a *testDNSServiceServer with
// the given profiles.
func newTestDNSServiceServer(tb testing.TB, prof []*dnspb.DNSProfile) (srv *testDNSServiceServer) {
	tb.Helper()

	syncTime := strconv.FormatInt(backendtest.TimeSync.UnixMilli(), 10)
	trailerMD := metadata.MD{"sync_time": []string{syncTime}}

	pt := testutil.NewPanicT(tb)

	srv = &testDNSServiceServer{
		OnCreateDeviceByHumanId: func(
			ctx context.Context,
			req *dnspb.CreateDeviceRequest,
		) (resp *dnspb.CreateDeviceResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		},

		OnGetDNSProfiles: func(
			_ *dnspb.DNSProfilesRequest,
			stream grpc.ServerStreamingServer[dnspb.DNSProfile],
		) (err error) {
			for _, p := range prof {
				sErr := stream.Send(p)
				require.NoError(pt, sErr)
			}

			stream.SetTrailer(trailerMD)

			return nil
		},

		OnSaveDevicesBillingStat: func(
			stream grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
		) (err error) {
			panic(testutil.UnexpectedCall(stream))
		},
	}

	return srv
}

func BenchmarkProfileStorage_Profiles(b *testing.B) {
	srvProf := backendtest.NewDNSProfile(b)
	srv := newTestDNSServiceServer(b, []*dnspb.DNSProfile{srvProf})

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(b, err)

	s, err := backendgrpc.NewProfileStorage(&backendgrpc.ProfileStorageConfig{
		Logger:           backendtest.Logger,
		BaseCustomLogger: backendtest.Logger,
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   l.Addr().String(),
		},
		ProfileAccessConstructor: backendtest.ProfileAccessConstructor,
		BindSet:                  netip.MustParsePrefix("0.0.0.0/0"),
		ErrColl:                  agdtest.NewErrorCollector(),
		GRPCMetrics:              backendgrpc.EmptyGRPCMetrics{},
		Metrics:                  backendgrpc.EmptyProfileDBMetrics{},
		MaxProfilesSize:          1 * datasize.MB,
	})
	require.NoError(b, err)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(1*time.Second),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterDNSServiceServer(grpcSrv, srv)

	go func() {
		pt := testutil.NewPanicT(b)

		srvErr := grpcSrv.Serve(l)
		require.NoError(pt, srvErr)
	}()
	b.Cleanup(grpcSrv.GracefulStop)

	ctx := context.Background()
	req := &profiledb.StorageProfilesRequest{}

	var resp *profiledb.StorageProfilesResponse

	b.ReportAllocs()
	for b.Loop() {
		resp, err = s.Profiles(ctx, req)
	}

	require.NoError(b, err)
	require.NotNil(b, resp)

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc
	//	cpu: Apple M1 Pro
	//	BenchmarkProfileStorage_Profiles-8   	    9096	    131193 ns/op	   22339 B/op	     379 allocs/op
}

// newTestDNSServer creates a new instance of [dnspb.DNSServiceServer] with the
// provided handlers for tests.  If one of the handlers is nil, then the call of
// it is estimated as unexpected.
func newTestDNSServer(
	tb testing.TB,
	onGetDNSProfiles func(
		req *dnspb.DNSProfilesRequest,
		srv grpc.ServerStreamingServer[dnspb.DNSProfile],
	) (err error),
	onSaveDevicesBillingStat func(
		srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
	) (err error),
	onCreateDeviceByHumanID func(
		ctx context.Context,
		req *dnspb.CreateDeviceRequest,
	) (resp *dnspb.CreateDeviceResponse, err error),
) (s dnspb.DNSServiceServer) {
	tb.Helper()

	if onGetDNSProfiles == nil {
		onGetDNSProfiles = func(
			req *dnspb.DNSProfilesRequest,
			srv grpc.ServerStreamingServer[dnspb.DNSProfile],
		) (err error) {
			panic(testutil.UnexpectedCall(req, srv))
		}
	}

	if onSaveDevicesBillingStat == nil {
		onSaveDevicesBillingStat = func(
			srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
		) (err error) {
			panic(testutil.UnexpectedCall(srv))
		}
	}

	if onCreateDeviceByHumanID == nil {
		onCreateDeviceByHumanID = func(
			ctx context.Context,
			req *dnspb.CreateDeviceRequest,
		) (resp *dnspb.CreateDeviceResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		}
	}

	s = &testDNSServiceServer{
		OnGetDNSProfiles:         onGetDNSProfiles,
		OnSaveDevicesBillingStat: onSaveDevicesBillingStat,
		OnCreateDeviceByHumanId:  onCreateDeviceByHumanID,
	}

	return s
}

// newTestOnGetDNSProfiles creates a new OnGetDNSProfiles handler for tests.
// srvProf, trailerCh and errCh must not be nil.
func newTestOnGetDNSProfiles(
	tb testing.TB,
	srvProf *dnspb.DNSProfile,
	trailerCh chan metadata.MD,
	errCh chan error,
) (h func(
	req *dnspb.DNSProfilesRequest,
	srv grpc.ServerStreamingServer[dnspb.DNSProfile],
) (err error),
) {
	tb.Helper()

	return func(
		_ *dnspb.DNSProfilesRequest,
		srv grpc.ServerStreamingServer[dnspb.DNSProfile],
	) (err error) {
		pt := testutil.NewPanicT(tb)

		sendErr := srv.Send(srvProf)
		require.NoError(pt, sendErr)

		trailerMD, ok := testutil.RequireReceive(pt, trailerCh, backendtest.Timeout)
		require.True(pt, ok)

		err, ok = testutil.RequireReceive(pt, errCh, backendtest.Timeout)
		require.True(pt, ok)

		srv.SetTrailer(trailerMD)

		return err
	}
}

// newTestOnCreateDevice creates a new OnCreateDeviceByHumanId handler for
// tests.  gotReqCh, respCh and errCh must not be nil.
func newTestOnCreateDevice(
	tb testing.TB,
	gotReqCh chan *dnspb.CreateDeviceRequest,
	respCh chan *dnspb.CreateDeviceResponse,
	errCh chan error,
) (h func(
	ctx context.Context,
	req *dnspb.CreateDeviceRequest,
) (resp *dnspb.CreateDeviceResponse, err error),
) {
	tb.Helper()

	return func(
		ctx context.Context,
		req *dnspb.CreateDeviceRequest,
	) (resp *dnspb.CreateDeviceResponse, err error) {
		pt := testutil.NewPanicT(tb)

		defer func() {
			testutil.RequireSend(pt, gotReqCh, req, backendtest.Timeout)
		}()

		response, ok := testutil.RequireReceive(pt, respCh, backendtest.Timeout)
		require.True(pt, ok)

		var respErr error
		respErr, ok = testutil.RequireReceive(pt, errCh, backendtest.Timeout)
		require.True(pt, ok)

		return response, respErr
	}
}

// newTestProfileStorage creates a new instance of *backendgrpc.ProfileStorage
// with test values.
func newTestProfileStorage(tb testing.TB, endpoint *url.URL) (s *backendgrpc.ProfileStorage) {
	tb.Helper()

	s, err := backendgrpc.NewProfileStorage(&backendgrpc.ProfileStorageConfig{
		Logger:                   backendtest.Logger,
		BaseCustomLogger:         backendtest.Logger,
		Endpoint:                 endpoint,
		ProfileAccessConstructor: backendtest.ProfileAccessConstructor,
		BindSet:                  backendtest.Bind,
		ErrColl:                  backendtest.ErrColl,
		GRPCMetrics:              backendgrpc.EmptyGRPCMetrics{},
		Metrics:                  backendgrpc.EmptyProfileDBMetrics{},
		MaxProfilesSize:          backendtest.ResponseSizeEstimate,
	})
	require.NoError(tb, err)

	return s
}
