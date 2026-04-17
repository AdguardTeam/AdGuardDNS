package main

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil"
	"google.golang.org/grpc/metadata"
)

// mockRateLimitServiceServer is the mock [dnspb.RateLimiteServiceServer].
type mockRateLimitServiceServer struct {
	dnspb.UnimplementedRateLimitServiceServer
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
var _ dnspb.RateLimitServiceServer = (*mockRateLimitServiceServer)(nil)

// Get implements the [dnspb.RateLimitServiceServer] interface for
// *mockRateLimitServiceServer.
func (s *mockRateLimitServiceServer) GetRateLimitSettings(
	ctx context.Context,
	req *dnspb.RateLimitSettingsRequest,
) (resp *dnspb.RateLimitSettingsResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &dnspb.RateLimitSettingsResponse{
		AllowedSubnets: []*dnspb.CidrRange{{
			Address: netutil.IPv4Localhost().AsSlice(),
			Prefix:  8,
		}},
	}, nil
}

// GetGlobalAccessSettings implements the [dnspb.RateLimitServiceServer]
// interface for *mockRateLimitServiceServer.
//
// TODO(a.garipov):  Implement this method.
func (s *mockRateLimitServiceServer) GetGlobalAccessSettings(
	ctx context.Context,
	req *dnspb.GlobalAccessSettingsRequest,
) (_ *dnspb.GlobalAccessSettingsResponse, _ error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &dnspb.GlobalAccessSettingsResponse{
		Standard: &dnspb.AccessSettings{
			AllowlistCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("10.10.10.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*dnspb.CidrRange{{
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
