package backendpb_test

import "github.com/AdguardTeam/AdGuardDNS/internal/backendpb"

// testDNSServiceServer is the [backendpb.DNSServiceServer] for tests.
//
// TODO(d.kolyshev): Use this to remove as much as possible from the internal
// test.
type testDNSServiceServer struct {
	backendpb.UnimplementedDNSServiceServer
	OnGetDNSProfiles func(
		req *backendpb.DNSProfilesRequest,
		srv backendpb.DNSService_GetDNSProfilesServer,
	) (err error)
	OnSaveDevicesBillingStat func(
		srv backendpb.DNSService_SaveDevicesBillingStatServer,
	) (err error)
}

// type check
var _ backendpb.DNSServiceServer = (*testDNSServiceServer)(nil)

// GetDNSProfiles implements the [backendpb.DNSServiceServer] interface for
// *testDNSServiceServer
func (s *testDNSServiceServer) GetDNSProfiles(
	req *backendpb.DNSProfilesRequest,
	srv backendpb.DNSService_GetDNSProfilesServer,
) (err error) {
	return s.OnGetDNSProfiles(req, srv)
}

// SaveDevicesBillingStat implements the [backendpb.DNSServiceServer] interface
// for *testDNSServiceServer
func (s *testDNSServiceServer) SaveDevicesBillingStat(
	srv backendpb.DNSService_SaveDevicesBillingStatServer,
) (err error) {
	return s.OnSaveDevicesBillingStat(srv)
}
