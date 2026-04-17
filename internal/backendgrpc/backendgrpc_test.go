package backendgrpc_test

import (
	"context"
	"net"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
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
		require.NoError(testutil.NewPanicT(tb), srvErr)
	}()
	tb.Cleanup(srv.GracefulStop)

	return &url.URL{
		Scheme: "grpc",
		Host:   l.Addr().String(),
	}
}

// testDNSServiceServer is the [dnspb.DNSServiceServer] for tests.
//
// TODO(d.kolyshev): Use this to remove as much as possible from the internal
// test.
type testDNSServiceServer struct {
	dnspb.UnimplementedDNSServiceServer

	//lint:ignore ST1003 Keep in sync with the generated code.
	OnCreateDeviceByHumanId func(
		ctx context.Context,
		req *dnspb.CreateDeviceRequest,
	) (resp *dnspb.CreateDeviceResponse, err error)

	OnGetDNSProfiles func(
		req *dnspb.DNSProfilesRequest,
		srv grpc.ServerStreamingServer[dnspb.DNSProfile],
	) (err error)

	OnSaveDevicesBillingStat func(
		srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
	) (err error)
}

// type check
var _ dnspb.DNSServiceServer = (*testDNSServiceServer)(nil)

// CreateDeviceByHumanId implements the [dnspb.DNSServiceServer] interface for
// *testDNSServiceServer.
//
//lint:ignore ST1003 Keep in sync with the generated code.
func (s *testDNSServiceServer) CreateDeviceByHumanId(
	ctx context.Context,
	req *dnspb.CreateDeviceRequest,
) (resp *dnspb.CreateDeviceResponse, err error) {
	return s.OnCreateDeviceByHumanId(ctx, req)
}

// GetDNSProfiles implements the [dnspb.DNSServiceServer] interface for
// *testDNSServiceServer
func (s *testDNSServiceServer) GetDNSProfiles(
	req *dnspb.DNSProfilesRequest,
	srv grpc.ServerStreamingServer[dnspb.DNSProfile],
) (err error) {
	return s.OnGetDNSProfiles(req, srv)
}

// SaveDevicesBillingStat implements the [dnspb.DNSServiceServer] interface
// for *testDNSServiceServer
func (s *testDNSServiceServer) SaveDevicesBillingStat(
	srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
) (err error) {
	return s.OnSaveDevicesBillingStat(srv)
}

// testFilterIndexServiceServer is the [dnspb.FilterIndexServiceServer] for
// tests.
type testFilterIndexServiceServer struct {
	dnspb.UnimplementedFilterIndexServiceServer

	OnGetTyposquattingFilterIndex func(
		ctx context.Context,
		req *dnspb.TyposquattingFilterIndexRequest,
	) (resp *dnspb.TyposquattingFilterIndexResponse, err error)
}

// type check
var _ dnspb.FilterIndexServiceServer = (*testFilterIndexServiceServer)(nil)

// GetTyposquattingFilterIndex implements the [dnspb.FilterIndexServiceServer]
// interface for *testFilterIndexServiceServer.
func (s *testFilterIndexServiceServer) GetTyposquattingFilterIndex(
	ctx context.Context,
	req *dnspb.TyposquattingFilterIndexRequest,
) (resp *dnspb.TyposquattingFilterIndexResponse, err error) {
	return s.OnGetTyposquattingFilterIndex(ctx, req)
}

// testRateLimitServiceServer is the [dnspb.RateLimitServiceServer] for tests.
type testRateLimitServiceServer struct {
	dnspb.UnimplementedRateLimitServiceServer

	OnGetRateLimitSettings func(
		ctx context.Context,
		req *dnspb.RateLimitSettingsRequest,
	) (resp *dnspb.RateLimitSettingsResponse, err error)

	OnGetGlobalAccessSettings func(
		ctx context.Context,
		req *dnspb.GlobalAccessSettingsRequest,
	) (resp *dnspb.GlobalAccessSettingsResponse, err error)
}

// type check
var _ dnspb.RateLimitServiceServer = (*testRateLimitServiceServer)(nil)

// GetRateLimitSettings implements the [dnspb.RateLimitServiceServer]
// interface for *testRateLimitServiceServer.
func (s *testRateLimitServiceServer) GetRateLimitSettings(
	ctx context.Context,
	req *dnspb.RateLimitSettingsRequest,
) (resp *dnspb.RateLimitSettingsResponse, err error) {
	return s.OnGetRateLimitSettings(ctx, req)
}

// GetGlobalAccessSettings implements the [dnspb.RateLimitServiceServer]
// interface for *testRateLimitServiceServer.
func (s *testRateLimitServiceServer) GetGlobalAccessSettings(
	ctx context.Context,
	req *dnspb.GlobalAccessSettingsRequest,
) (resp *dnspb.GlobalAccessSettingsResponse, err error) {
	return s.OnGetGlobalAccessSettings(ctx, req)
}

// testRemoteKVServiceServer is the [dnspb.RemoteKVServiceServer] for tests.
type testRemoteKVServiceServer struct {
	dnspb.UnimplementedRemoteKVServiceServer

	OnGet func(
		ctx context.Context,
		req *dnspb.RemoteKVGetRequest,
	) (resp *dnspb.RemoteKVGetResponse, err error)

	OnSet func(
		ctx context.Context,
		req *dnspb.RemoteKVSetRequest,
	) (resp *dnspb.RemoteKVSetResponse, err error)
}

// type check
var _ dnspb.RemoteKVServiceServer = (*testRemoteKVServiceServer)(nil)

// Get implements the [dnspb.RemoteKVServiceServer] interface for
// *testRemoteKVServiceServer.
func (s *testRemoteKVServiceServer) Get(
	ctx context.Context,
	req *dnspb.RemoteKVGetRequest,
) (resp *dnspb.RemoteKVGetResponse, err error) {
	return s.OnGet(ctx, req)
}

// Set implements the [dnspb.RemoteKVServiceServer] interface for
// *testRemoteKVServiceServer.
func (s *testRemoteKVServiceServer) Set(
	ctx context.Context,
	req *dnspb.RemoteKVSetRequest,
) (resp *dnspb.RemoteKVSetResponse, err error) {
	return s.OnSet(ctx, req)
}

// testSessionTicketServiceServer is the [dnspb.SessionTicketServiceServer] for
// tests.
type testSessionTicketServiceServer struct {
	dnspb.UnimplementedSessionTicketServiceServer

	OnGetSessionTickets func(
		ctx context.Context,
		req *dnspb.SessionTicketRequest,
	) (resp *dnspb.SessionTicketResponse, err error)
}

// type check
var _ dnspb.SessionTicketServiceServer = (*testSessionTicketServiceServer)(nil)

// GetSessionTickets implements the [dnspb.SessionTicketServiceServer] interface
// for *testSessionTicketServiceServer.
func (s *testSessionTicketServiceServer) GetSessionTickets(
	ctx context.Context,
	req *dnspb.SessionTicketRequest,
) (resp *dnspb.SessionTicketResponse, err error) {
	return s.OnGetSessionTickets(ctx, req)
}

// testCustomDomainServiceServer is the [dnspb.CustomDomainServiceServer] for
// tests.
type testCustomDomainServiceServer struct {
	dnspb.UnimplementedCustomDomainServiceServer

	OnGetCustomDomainCertificate func(
		ctx context.Context,
		req *dnspb.CustomDomainCertificateRequest,
	) (resp *dnspb.CustomDomainCertificateResponse, err error)
}

// type check
var _ dnspb.CustomDomainServiceServer = (*testCustomDomainServiceServer)(nil)

// GetCustomDomainCertificate implements the [dnspb.CustomDomainServiceServer]
// interface for *testCustomDomainServiceServer.
func (s *testCustomDomainServiceServer) GetCustomDomainCertificate(
	ctx context.Context,
	req *dnspb.CustomDomainCertificateRequest,
) (resp *dnspb.CustomDomainCertificateResponse, err error) {
	return s.OnGetCustomDomainCertificate(ctx, req)
}
