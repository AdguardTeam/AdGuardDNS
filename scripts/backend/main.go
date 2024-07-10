// backend contains mock GRPC server for BILLSTAT_URL and PROFILES_URL
// endpoints.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	l := slogutil.New(nil)

	const listenAddr = "localhost:6062"
	lsnr, err := net.Listen("tcp", listenAddr)
	if err != nil {
		l.Error("getting listener", slogutil.KeyError, err)

		os.Exit(osutil.ExitCodeFailure)
	}

	grpcSrv := grpc.NewServer()
	srv := &mockDNSServiceServer{
		log: slogutil.New(nil),
	}
	backendpb.RegisterDNSServiceServer(grpcSrv, srv)

	l.Info("staring serving", "laddr", listenAddr)
	err = grpcSrv.Serve(lsnr)
	if err != nil {
		l.Error("serving grpc", slogutil.KeyError, err)

		os.Exit(osutil.ExitCodeFailure)
	}
}

// mockDNSServiceServer is the mock [backendpb.DNSServiceServer].
type mockDNSServiceServer struct {
	backendpb.UnimplementedDNSServiceServer
	log *slog.Logger
}

// type check
var _ backendpb.DNSServiceServer = (*mockDNSServiceServer)(nil)

// CreateDeviceByHumanId implements the [backendpb.DNSServiceServer] interface
// for *mockDNSServiceServer.
//
//lint:ignore ST1003 The name is necessary for the interface.
func (s *mockDNSServiceServer) CreateDeviceByHumanId(
	ctx context.Context,
	req *backendpb.CreateDeviceRequest,
) (resp *backendpb.CreateDeviceResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"creating by id",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	p := newDNSProfile()

	return &backendpb.CreateDeviceResponse{
		Device: p.Devices[1],
	}, nil
}

// GetDNSProfiles implements the [backendpb.DNSServiceServer] interface for
// *mockDNSServiceServer
func (s *mockDNSServiceServer) GetDNSProfiles(
	req *backendpb.DNSProfilesRequest,
	srv backendpb.DNSService_GetDNSProfilesServer,
) (err error) {
	ctx := srv.Context()
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"getting dns profiles",
		"auth", md.Get(httphdr.Authorization),
		"sync_time", req.SyncTime.AsTime(),
	)

	t := time.Now()
	syncTime := strconv.FormatInt(t.UnixMilli(), 10)
	trailerMD := metadata.MD{
		"sync_time": []string{syncTime},
	}

	srv.SetTrailer(trailerMD)
	err = srv.Send(newDNSProfile())
	if err != nil {
		s.log.WarnContext(ctx, "sending dns profile", slogutil.KeyError, err)
	}

	return nil
}

// SaveDevicesBillingStat implements the [backendpb.DNSServiceServer] interface
// for *mockDNSServiceServer
func (s *mockDNSServiceServer) SaveDevicesBillingStat(
	srv backendpb.DNSService_SaveDevicesBillingStatServer,
) (err error) {
	ctx := srv.Context()
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(ctx, "saving devices", "auth", md.Get(httphdr.Authorization))

	for {
		var bs *backendpb.DeviceBillingStat
		bs, err = srv.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return srv.SendAndClose(&emptypb.Empty{})
			} else {
				return fmt.Errorf("receiving billing stat: %w", err)
			}
		}

		s.log.InfoContext(ctx, "saving billing stat", "device_id", bs.DeviceId)
	}
}

// newDNSProfile returns a mock instance of [*backendpb.DNSProfile].
func newDNSProfile() (dp *backendpb.DNSProfile) {
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
	}, {
		Id:           "auto",
		Name:         "My Device X-10",
		HumanIdLower: "my-device-x--10",
	}}

	return &backendpb.DNSProfile{
		DnsId:              "mock1234",
		FilteringEnabled:   true,
		QueryLogEnabled:    true,
		Deleted:            false,
		AutoDevicesEnabled: true,
		IpLogEnabled:       true,
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
