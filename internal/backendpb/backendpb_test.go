package backendpb_test

import (
	"context"
	"net"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// runLocalGRPCServer starts a gRPC server on localhost and returns its
// endpoint.  It also registers a cleanup for graceful shutdown.
func runLocalGRPCServer(tb testing.TB, srv *grpc.Server) (u *url.URL) {
	tb.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	go func() {
		srvErr := srv.Serve(l)
		require.NoError(testutil.PanicT{}, srvErr)
	}()
	tb.Cleanup(srv.GracefulStop)

	return &url.URL{
		Scheme: "grpc",
		Host:   l.Addr().String(),
	}
}

// testDNSServiceServer is the [backendpb.DNSServiceServer] for tests.
//
// TODO(d.kolyshev): Use this to remove as much as possible from the internal
// test.
type testDNSServiceServer struct {
	backendpb.UnimplementedDNSServiceServer

	//lint:ignore ST1003 Keep in sync with the generated code.
	OnCreateDeviceByHumanId func(
		ctx context.Context,
		req *backendpb.CreateDeviceRequest,
	) (resp *backendpb.CreateDeviceResponse, err error)

	OnGetDNSProfiles func(
		req *backendpb.DNSProfilesRequest,
		srv grpc.ServerStreamingServer[backendpb.DNSProfile],
	) (err error)

	OnSaveDevicesBillingStat func(
		srv grpc.ClientStreamingServer[backendpb.DeviceBillingStat, emptypb.Empty],
	) (err error)
}

// type check
var _ backendpb.DNSServiceServer = (*testDNSServiceServer)(nil)

// CreateDeviceByHumanId implements the [backendpb.DNSServiceServer] interface
// for *testDNSServiceServer.
//
//lint:ignore ST1003 Keep in sync with the generated code.
func (s *testDNSServiceServer) CreateDeviceByHumanId(
	ctx context.Context,
	req *backendpb.CreateDeviceRequest,
) (resp *backendpb.CreateDeviceResponse, err error) {
	return s.OnCreateDeviceByHumanId(ctx, req)
}

// GetDNSProfiles implements the [backendpb.DNSServiceServer] interface for
// *testDNSServiceServer
func (s *testDNSServiceServer) GetDNSProfiles(
	req *backendpb.DNSProfilesRequest,
	srv grpc.ServerStreamingServer[backendpb.DNSProfile],
) (err error) {
	return s.OnGetDNSProfiles(req, srv)
}

// SaveDevicesBillingStat implements the [backendpb.DNSServiceServer] interface
// for *testDNSServiceServer
func (s *testDNSServiceServer) SaveDevicesBillingStat(
	srv grpc.ClientStreamingServer[backendpb.DeviceBillingStat, emptypb.Empty],
) (err error) {
	return s.OnSaveDevicesBillingStat(srv)
}

// testRateLimitServiceServer is the [backendpb.RateLimitServiceServer] for
// tests.
type testRateLimitServiceServer struct {
	backendpb.UnimplementedRateLimitServiceServer

	OnGetRateLimitSettings func(
		ctx context.Context,
		req *backendpb.RateLimitSettingsRequest,
	) (resp *backendpb.RateLimitSettingsResponse, err error)

	OnGetGlobalAccessSettings func(
		ctx context.Context,
		req *backendpb.GlobalAccessSettingsRequest,
	) (resp *backendpb.GlobalAccessSettingsResponse, err error)
}

// type check
var _ backendpb.RateLimitServiceServer = (*testRateLimitServiceServer)(nil)

// GetRateLimitSettings implements the [backendpb.RateLimitServiceServer]
// interface for *testRateLimitServiceServer.
func (s *testRateLimitServiceServer) GetRateLimitSettings(
	ctx context.Context,
	req *backendpb.RateLimitSettingsRequest,
) (resp *backendpb.RateLimitSettingsResponse, err error) {
	return s.OnGetRateLimitSettings(ctx, req)
}

// GetGlobalAccessSettings implements the [backendpb.RateLimitServiceServer]
// interface for *testRateLimitServiceServer.
func (s *testRateLimitServiceServer) GetGlobalAccessSettings(
	ctx context.Context,
	req *backendpb.GlobalAccessSettingsRequest,
) (resp *backendpb.GlobalAccessSettingsResponse, err error) {
	return s.OnGetGlobalAccessSettings(ctx, req)
}

// testRemoteKVServiceServer is the [backendpb.RemoteKVServiceServer] for tests.
type testRemoteKVServiceServer struct {
	backendpb.UnimplementedRemoteKVServiceServer

	OnGet func(
		ctx context.Context,
		req *backendpb.RemoteKVGetRequest,
	) (resp *backendpb.RemoteKVGetResponse, err error)

	OnSet func(
		ctx context.Context,
		req *backendpb.RemoteKVSetRequest,
	) (resp *backendpb.RemoteKVSetResponse, err error)
}

// type check
var _ backendpb.RemoteKVServiceServer = (*testRemoteKVServiceServer)(nil)

// Get implements the [backendpb.RemoteKVServiceServer] interface for
// *testRemoteKVServiceServer.
func (s *testRemoteKVServiceServer) Get(
	ctx context.Context,
	req *backendpb.RemoteKVGetRequest,
) (resp *backendpb.RemoteKVGetResponse, err error) {
	return s.OnGet(ctx, req)
}

// Set implements the [backendpb.RemoteKVServiceServer] interface for
// *testRemoteKVServiceServer.
func (s *testRemoteKVServiceServer) Set(
	ctx context.Context,
	req *backendpb.RemoteKVSetRequest,
) (resp *backendpb.RemoteKVSetResponse, err error) {
	return s.OnSet(ctx, req)
}

// testSessionTicketServiceServer is the [backendpb.SessionTicketServiceServer]
// for tests.
type testSessionTicketServiceServer struct {
	backendpb.UnimplementedSessionTicketServiceServer

	OnGetSessionTickets func(
		ctx context.Context,
		req *backendpb.SessionTicketRequest,
	) (resp *backendpb.SessionTicketResponse, err error)
}

// type check
var _ backendpb.SessionTicketServiceServer = (*testSessionTicketServiceServer)(nil)

// GetSessionTickets implements the [backendpb.SessionTicketServiceServer]
// interface for *testSessionTicketServiceServer.
func (s *testSessionTicketServiceServer) GetSessionTickets(
	ctx context.Context,
	req *backendpb.SessionTicketRequest,
) (resp *backendpb.SessionTicketResponse, err error) {
	return s.OnGetSessionTickets(ctx, req)
}
