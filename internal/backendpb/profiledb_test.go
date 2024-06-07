package backendpb_test

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	errSink  error
	respSink *profiledb.StorageResponse
)

func BenchmarkProfileStorage_Profiles(b *testing.B) {
	syncTime := strconv.FormatInt(backendpb.TestUpdTime.UnixMilli(), 10)
	srvProf := backendpb.NewTestDNSProfile(b)
	trailerMD := metadata.MD{
		"sync_time": []string{syncTime},
	}

	srv := &testDNSServiceServer{
		OnGetDNSProfiles: func(
			req *backendpb.DNSProfilesRequest,
			srv backendpb.DNSService_GetDNSProfilesServer,
		) (err error) {
			sendErr := srv.Send(srvProf)
			srv.SetTrailer(trailerMD)

			return sendErr
		},
	}

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic(err)
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(b, err)

	s, err := backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
		BindSet: netip.MustParsePrefix("0.0.0.0/0"),
		ErrColl: errColl,
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   l.Addr().String(),
		},
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
	req := &profiledb.StorageRequest{}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		respSink, errSink = s.Profiles(ctx, req)
	}

	require.NoError(b, errSink)
	require.NotNil(b, respSink)

	// Most recent result, on a ThinkPad X13:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendpb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkProfileStorage_Profiles
	//	BenchmarkProfileStorage_Profiles-16         5347            245341 ns/op           15129 B/op      265 allocs/op
}
