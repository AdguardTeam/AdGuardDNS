package main

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil"
	"google.golang.org/grpc/metadata"
)

// mockRateLimitServiceServer is the mock [backendpb.RateLimiteServiceServer].
type mockRateLimitServiceServer struct {
	backendpb.UnimplementedRateLimitServiceServer
	log *slog.Logger
}

// newMockRateLimitServiceServer creates a new instance of
// *mockRateLimitServiceServer.
func newMockRateLimitServiceServer(log *slog.Logger) (srv *mockRateLimitServiceServer) {
	return &mockRateLimitServiceServer{
		log: log,
	}
}

// type check
var _ backendpb.RateLimitServiceServer = (*mockRateLimitServiceServer)(nil)

// Get implements the [backendpb.RateLimitServiceServer] interface for
// *mockRateLimitServiceServer.
func (s *mockRateLimitServiceServer) GetRateLimitSettings(
	ctx context.Context,
	req *backendpb.RateLimitSettingsRequest,
) (resp *backendpb.RateLimitSettingsResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &backendpb.RateLimitSettingsResponse{
		AllowedSubnets: []*backendpb.CidrRange{{
			Address: netutil.IPv4Localhost().AsSlice(),
			Prefix:  8,
		}},
	}, nil
}

// GetGlobalAccessSettings implements the [backendpb.RateLimitServiceServer]
// interface for *mockRateLimitServiceServer.
//
// TODO(a.garipov):  Implement this method.
func (s *mockRateLimitServiceServer) GetGlobalAccessSettings(
	ctx context.Context,
	req *backendpb.GlobalAccessSettingsRequest,
) (_ *backendpb.GlobalAccessSettingsResponse, _ error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &backendpb.GlobalAccessSettingsResponse{
		Standard: &backendpb.AccessSettings{
			AllowlistCidr: []*backendpb.CidrRange{{
				Address: netip.MustParseAddr("10.10.10.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*backendpb.CidrRange{{
				Address: netip.MustParseAddr("20.20.20.0").AsSlice(),
				Prefix:  24,
			}},
			AllowlistAsn:         []uint32{10},
			BlocklistAsn:         []uint32{20},
			BlocklistDomainRules: []string{"block.std.test"},
			Enabled:              true,
		},
	}, nil
}
