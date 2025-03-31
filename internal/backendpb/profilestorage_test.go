package backendpb_test

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
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
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

func TestProfileStorage_CreateAutoDevice(t *testing.T) {
	t.Parallel()

	const devType = agd.DeviceTypeOther

	gotReqCh := make(chan *backendpb.CreateDeviceRequest, 1)

	srv := &testDNSServiceServer{
		OnCreateDeviceByHumanId: func(
			ctx context.Context,
			req *backendpb.CreateDeviceRequest,
		) (resp *backendpb.CreateDeviceResponse, err error) {
			defer func() {
				pt := testutil.PanicT{}
				testutil.RequireSend(pt, gotReqCh, req, testTimeout)
			}()

			return &backendpb.CreateDeviceResponse{
				Device: &backendpb.DeviceSettings{
					Id:           backendpb.TestDeviceIDStr,
					HumanIdLower: backendpb.TestHumanIDLowerStr,
				},
			}, nil
		},

		OnGetDNSProfiles: func(
			req *backendpb.DNSProfilesRequest,
			srv grpc.ServerStreamingServer[backendpb.DNSProfile],
		) (err error) {
			panic("not implemented")
		},

		OnSaveDevicesBillingStat: func(
			srv grpc.ClientStreamingServer[backendpb.DeviceBillingStat, emptypb.Empty],
		) (err error) {
			panic("not implemented")
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	s, err := backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
		BindSet:          backendpb.TestBind,
		ErrColl:          agdtest.NewErrorCollector(),
		Logger:           backendpb.TestLogger,
		BaseCustomLogger: backendpb.TestLogger,
		GRPCMetrics:      backendpb.EmptyGRPCMetrics{},
		Metrics:          backendpb.EmptyProfileDBMetrics{},
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   l.Addr().String(),
		},
	})
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(1*time.Second),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterDNSServiceServer(grpcSrv, srv)

	go func() {
		pt := &testutil.PanicT{}

		srvErr := grpcSrv.Serve(l)
		require.NoError(pt, srvErr)
	}()
	t.Cleanup(grpcSrv.GracefulStop)

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	resp, err := s.CreateAutoDevice(ctx, &profiledb.StorageCreateAutoDeviceRequest{
		ProfileID:  backendpb.TestProfileID,
		HumanID:    backendpb.TestHumanID,
		DeviceType: devType,
	})
	assert.NoError(t, err)

	gotReq, ok := testutil.RequireReceive(t, gotReqCh, testTimeout)
	require.True(t, ok)
	require.NotNil(t, gotReq)

	assert.Equal(t, backendpb.TestProfileIDStr, gotReq.DnsId)
	assert.Equal(t, backendpb.TestHumanIDStr, gotReq.HumanId)
	assert.Equal(t, backendpb.DeviceType(devType), gotReq.DeviceType)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Device)

	assert.Equal(t, backendpb.TestDeviceID, resp.Device.ID)
	assert.Equal(t, backendpb.TestHumanIDLower, resp.Device.HumanIDLower)
}

var (
	errSink  error
	respSink *profiledb.StorageProfilesResponse
)

func BenchmarkProfileStorage_Profiles(b *testing.B) {
	syncTime := strconv.FormatInt(backendpb.TestSyncTime.UnixMilli(), 10)
	srvProf := backendpb.NewTestDNSProfile(b)
	trailerMD := metadata.MD{
		"sync_time": []string{syncTime},
	}

	srv := &testDNSServiceServer{
		OnCreateDeviceByHumanId: func(
			ctx context.Context,
			req *backendpb.CreateDeviceRequest,
		) (resp *backendpb.CreateDeviceResponse, err error) {
			panic("not implemented")
		},

		OnGetDNSProfiles: func(
			req *backendpb.DNSProfilesRequest,
			srv grpc.ServerStreamingServer[backendpb.DNSProfile],
		) (err error) {
			sendErr := srv.Send(srvProf)
			srv.SetTrailer(trailerMD)

			return sendErr
		},

		OnSaveDevicesBillingStat: func(
			srv grpc.ClientStreamingServer[backendpb.DeviceBillingStat, emptypb.Empty],
		) (err error) {
			panic("not implemented")
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(b, err)

	s, err := backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
		BindSet:          netip.MustParsePrefix("0.0.0.0/0"),
		ErrColl:          agdtest.NewErrorCollector(),
		Logger:           backendpb.TestLogger,
		BaseCustomLogger: backendpb.TestLogger,
		GRPCMetrics:      backendpb.EmptyGRPCMetrics{},
		Metrics:          backendpb.EmptyProfileDBMetrics{},
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   l.Addr().String(),
		},
		MaxProfilesSize: 1 * datasize.MB,
	})
	require.NoError(b, err)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(1*time.Second),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterDNSServiceServer(grpcSrv, srv)

	go func() {
		pt := &testutil.PanicT{}

		srvErr := grpcSrv.Serve(l)
		require.NoError(pt, srvErr)
	}()
	b.Cleanup(grpcSrv.GracefulStop)

	ctx := context.Background()
	req := &profiledb.StorageProfilesRequest{}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		respSink, errSink = s.Profiles(ctx, req)
	}

	require.NoError(b, errSink)
	require.NotNil(b, respSink)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendpb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkProfileStorage_Profiles-16    	    4501	    258657 ns/op	   20020 B/op	     350 allocs/op
}
