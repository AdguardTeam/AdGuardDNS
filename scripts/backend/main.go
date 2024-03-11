// backend contains mock GRPC server for BILLSTAT_URL and PROFILES_URL
// endpoints.
package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	const listenAddr = "localhost:6062"
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("getting listener: %s", err)
	}

	grpcSrv := grpc.NewServer()
	srv := &mockDNSServiceServer{}
	backendpb.RegisterDNSServiceServer(grpcSrv, srv)

	log.Info("staring serving on %s", listenAddr)
	err = grpcSrv.Serve(l)
	if err != nil {
		log.Fatalf("serving grpc: %s", err)
	}
}

// mockDNSServiceServer is the mock [backendpb.DNSServiceServer].
type mockDNSServiceServer struct {
	backendpb.UnimplementedDNSServiceServer
}

// type check
var _ backendpb.DNSServiceServer = (*mockDNSServiceServer)(nil)

// GetDNSProfiles implements the [backendpb.DNSServiceServer] interface for
// *mockDNSServiceServer
func (s *mockDNSServiceServer) GetDNSProfiles(
	req *backendpb.DNSProfilesRequest,
	srv backendpb.DNSService_GetDNSProfilesServer,
) (err error) {
	log.Info("getting dns profiles: sync time: %s", req.SyncTime.AsTime())

	t := time.Now()
	syncTime := strconv.FormatInt(t.UnixMilli(), 10)
	trailerMD := metadata.MD{
		"sync_time": []string{syncTime},
	}

	srv.SetTrailer(trailerMD)
	err = srv.Send(mockDNSProfile())
	if err != nil {
		log.Info("sending dns profile: %s", err)
	}

	return nil
}

// SaveDevicesBillingStat implements the [backendpb.DNSServiceServer] interface
// for *mockDNSServiceServer
func (s *mockDNSServiceServer) SaveDevicesBillingStat(
	srv backendpb.DNSService_SaveDevicesBillingStatServer,
) (err error) {
	for {
		bs, err := srv.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return srv.SendAndClose(&emptypb.Empty{})
			} else {
				return fmt.Errorf("receiving billing stat: %w", err)
			}
		}

		log.Info("saving billing stat: device: %q", bs.DeviceId)
	}
}

// mockDNSProfile returns a mock instance of [*backendpb.DNSProfile].
func mockDNSProfile() (dp *backendpb.DNSProfile) {
	dayRange := &backendpb.DayRange{
		Start: durationpb.New(0),
		End:   durationpb.New(59 * time.Minute),
	}

	devices := []*backendpb.DeviceSettings{{
		Id:               "test",
		Name:             "test-name",
		FilteringEnabled: false,
		LinkedIp:         []byte{1, 1, 1, 1},
		DedicatedIps:     [][]byte{{127, 0, 0, 1}},
	}}

	return &backendpb.DNSProfile{
		DnsId:            "mock1234",
		FilteringEnabled: true,
		QueryLogEnabled:  true,
		Deleted:          false,
		SafeBrowsing: &backendpb.SafeBrowsingSettings{
			Enabled:               true,
			BlockDangerousDomains: true,
			BlockNrd:              false,
		},
		Parental: &backendpb.ParentalSettings{
			Enabled:           false,
			BlockAdult:        false,
			GeneralSafeSearch: false,
			YoutubeSafeSearch: false,
			BlockedServices:   []string{"youtube"},
			Schedule: &backendpb.ScheduleSettings{
				Tmz: "GMT",
				WeeklyRange: &backendpb.WeeklyRange{
					Sun: nil,
					Mon: dayRange,
					Tue: dayRange,
					Wed: dayRange,
					Thu: dayRange,
					Fri: dayRange,
					Sat: nil,
				},
			},
		},
		Access: &backendpb.AccessSettings{
			AllowlistCidr: []*backendpb.CidrRange{{
				Address: netip.MustParseAddr("1.1.1.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*backendpb.CidrRange{{
				Address: netip.MustParseAddr("2.2.2.0").AsSlice(),
				Prefix:  24,
			}},
			AllowlistAsn:         []uint32{1},
			BlocklistAsn:         []uint32{2},
			BlocklistDomainRules: []string{"block.test"},
		},
		RuleLists: &backendpb.RuleListsSettings{
			Enabled: true,
			Ids:     []string{"1"},
		},
		Devices:             devices,
		CustomRules:         []string{"||example.org^"},
		FilteredResponseTtl: durationpb.New(10 * time.Second),
		BlockPrivateRelay:   true,
		BlockFirefoxCanary:  true,
		BlockingMode: &backendpb.DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &backendpb.BlockingModeCustomIP{
				Ipv4: []byte{1, 2, 3, 4},
			},
		},
	}
}
