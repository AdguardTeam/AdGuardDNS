package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockDNSServiceServer is the mock [dnspb.DNSServiceServer].
type mockDNSServiceServer struct {
	dnspb.UnimplementedDNSServiceServer
	logger *slog.Logger
}

// newMockDNSServiceServer creates a new instance of *mockDNSServiceServer.
// logger must not be nil.
func newMockDNSServiceServer(logger *slog.Logger) (srv *mockDNSServiceServer) {
	return &mockDNSServiceServer{
		logger: logger,
	}
}

// type check
var _ dnspb.DNSServiceServer = (*mockDNSServiceServer)(nil)

// CreateDeviceByHumanId implements the [dnspb.DNSServiceServer] interface
// for *mockDNSServiceServer.
//
//lint:ignore ST1003 The name is necessary for the interface.
func (s *mockDNSServiceServer) CreateDeviceByHumanId(
	ctx context.Context,
	req *dnspb.CreateDeviceRequest,
) (resp *dnspb.CreateDeviceResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.logger.InfoContext(
		ctx,
		"creating by id",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	p := s.newDNSProfile(true)

	return &dnspb.CreateDeviceResponse{
		Device: p.Devices[1],
	}, nil
}

// GetDNSProfiles implements the [dnspb.DNSServiceServer] interface for
// *mockDNSServiceServer
func (s *mockDNSServiceServer) GetDNSProfiles(
	req *dnspb.DNSProfilesRequest,
	srv grpc.ServerStreamingServer[dnspb.DNSProfile],
) (err error) {
	ctx := srv.Context()
	md, _ := metadata.FromIncomingContext(ctx)
	reqSyncTime := req.SyncTime.AsTime()
	isFullSync := reqSyncTime.IsZero()
	s.logger.InfoContext(
		ctx,
		"getting dns profiles",
		"auth", md.Get(httphdr.Authorization),
		"sync_time", reqSyncTime,
		"is_full", isFullSync,
	)

	t := time.Now()
	syncTime := strconv.FormatInt(t.UnixMilli(), 10)
	trailerMD := metadata.MD{
		"sync_time": []string{syncTime},
	}

	srv.SetTrailer(trailerMD)

	err = srv.Send(s.newDNSProfile(isFullSync))
	if err != nil {
		s.logger.WarnContext(ctx, "sending dns profile", slogutil.KeyError, err)
	}

	return nil
}

// SaveDevicesBillingStat implements the [dnspb.DNSServiceServer] interface for
// *mockDNSServiceServer
func (s *mockDNSServiceServer) SaveDevicesBillingStat(
	srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
) (err error) {
	ctx := srv.Context()
	md, _ := metadata.FromIncomingContext(ctx)
	s.logger.InfoContext(ctx, "saving devices", "auth", md.Get(httphdr.Authorization))

	for {
		var bs *dnspb.DeviceBillingStat
		bs, err = srv.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return srv.SendAndClose(&emptypb.Empty{})
			} else {
				return fmt.Errorf("receiving billing stat: %w", err)
			}
		}

		s.logger.InfoContext(ctx, "saving billing stat", "device_id", bs.DeviceId)
	}
}

// newDNSProfile returns a mock instance of [*dnspb.DNSProfile].  If isFullSync
// is true, it returns a full profile; otherwise, it returns device changes.
func (s *mockDNSServiceServer) newDNSProfile(isFullSync bool) (dp *dnspb.DNSProfile) {
	dayRange := &dnspb.DayRange{
		Start: durationpb.New(0),
		End:   durationpb.New(59 * time.Minute),
	}

	const (
		devIDAuto = "didauto1"
		devIDTest = "didtest1"
	)

	devTest := &dnspb.DeviceSettings{
		Id:               devIDTest,
		Name:             time.Now().Format("Test Name 2006-01-02T15:04:05"),
		FilteringEnabled: true,
		LinkedIp:         []byte{1, 1, 1, 1},
		DedicatedIps:     [][]byte{{127, 0, 0, 1}},
	}

	var (
		devices       []*dnspb.DeviceSettings
		deviceChanges []*dnspb.DeviceSettingsChange
	)
	if isFullSync {
		devices = []*dnspb.DeviceSettings{
			devTest,
			{
				Id:           devIDAuto,
				Name:         "My Device X-10",
				HumanIdLower: "my-device-x--10",
			},
		}
	} else {
		deviceChanges = []*dnspb.DeviceSettingsChange{{
			Change: &dnspb.DeviceSettingsChange_Upserted_{
				Upserted: &dnspb.DeviceSettingsChange_Upserted{Device: devTest},
			},
		}, {
			Change: &dnspb.DeviceSettingsChange_Deleted_{
				Deleted: &dnspb.DeviceSettingsChange_Deleted{DeviceId: devIDAuto},
			},
		}}
	}

	week := &dnspb.WeeklyRange{
		Sun: nil,
		Mon: dayRange,
		Tue: dayRange,
		Wed: dayRange,
		Thu: dayRange,
		Fri: dayRange,
		Sat: nil,
	}

	customDomainCurrent := &dnspb.CustomDomain{
		Domains: []string{
			"current-1.domain.example",
			"current-2.domain.example",
		},
		State: &dnspb.CustomDomain_Current_{
			Current: &dnspb.CustomDomain_Current{
				CertName:  "abcdefgh",
				NotBefore: timestamppb.New(time.Now().Add(-24 * time.Hour)),
				NotAfter:  timestamppb.New(time.Now().Add(24 * time.Hour)),
				Enabled:   true,
			},
		},
	}

	customDomainPending := &dnspb.CustomDomain{
		Domains: []string{
			"pending-1.domain.example",
			"pending-2.domain.example",
		},
		State: &dnspb.CustomDomain_Pending_{
			Pending: &dnspb.CustomDomain_Pending{
				WellKnownPath: "/.well-known/abc/def",
				Expire:        timestamppb.New(time.Now().Add(24 * time.Hour)),
			},
		},
	}

	customDomain := &dnspb.CustomDomainSettings{
		Domains: []*dnspb.CustomDomain{
			customDomainCurrent,
			customDomainPending,
		},
		Enabled: true,
	}

	return &dnspb.DNSProfile{
		DnsId:              "mock1234",
		FilteringEnabled:   true,
		QueryLogEnabled:    true,
		Deleted:            false,
		AutoDevicesEnabled: true,
		IpLogEnabled:       true,
		SafeBrowsing: &dnspb.SafeBrowsingSettings{
			Typosquatting: &dnspb.TyposquattingFilterSettings{
				Enabled: true,
			},
			Enabled:               true,
			BlockDangerousDomains: true,
			BlockNrd:              false,
		},
		Parental: &dnspb.ParentalSettings{
			Enabled:           false,
			BlockAdult:        false,
			GeneralSafeSearch: false,
			YoutubeSafeSearch: false,
			BlockedServices:   []string{"youtube"},
			Schedule: &dnspb.ScheduleSettings{
				Tmz:         "GMT",
				WeeklyRange: week,
			},
		},
		Access: &dnspb.AccessSettings{
			AllowlistCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("1.1.1.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("2.2.2.0").AsSlice(),
				Prefix:  24,
			}},
			AllowlistAsn:         []uint32{1},
			BlocklistAsn:         []uint32{2},
			BlocklistDomainRules: []string{"block.test"},
			Enabled:              true,
		},
		CustomRuleLists: &dnspb.CustomRuleListsSettings{
			Ids:     []string{"1"},
			Enabled: true,
		},
		RuleLists: &dnspb.RuleListsSettings{
			Ids:     []string{"2"},
			Enabled: true,
		},
		Devices:             devices,
		CustomRules:         []string{"||example.org^"},
		FilteredResponseTtl: durationpb.New(10 * time.Second),
		BlockChromePrefetch: true,
		BlockFirefoxCanary:  true,
		BlockPrivateRelay:   true,
		AdultBlockingMode: &dnspb.DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: []byte{1, 1, 1, 1},
			},
		},
		BlockingMode: &dnspb.DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: []byte{1, 2, 3, 4},
			},
		},
		SafeBrowsingBlockingMode: &dnspb.DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: []byte{2, 2, 2, 2},
			},
		},
		RateLimit: &dnspb.RateLimitSettings{
			ClientCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("3.3.3.0").AsSlice(),
				Prefix:  24,
			}},
			Rps:     100,
			Enabled: true,
		},
		CustomDomain: customDomain,
		CategoryFilter: &dnspb.CategoryFilterSettings{
			Ids:     []string{"games"},
			Enabled: true,
		},
		AccountIdInt:                  1234,
		DeviceChanges:                 deviceChanges,
		StandardAccessSettingsEnabled: true,
		QueryLogStream:                false,
	}
}
