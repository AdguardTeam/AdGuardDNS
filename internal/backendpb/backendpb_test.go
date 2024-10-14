package backendpb_test

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

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
