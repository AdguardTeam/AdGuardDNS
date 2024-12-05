package backendpb_test

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testRateLimitServiceServer is the [backendpb.RateLimitServiceServer] for
// tests.
type testRateLimitServiceServer struct {
	backendpb.UnimplementedRateLimitServiceServer

	OnGetRateLimitSettings func(
		ctx context.Context,
		req *backendpb.RateLimitSettingsRequest,
	) (resp *backendpb.RateLimitSettingsResponse, err error)
}

// type check
var _ backendpb.DNSServiceServer = (*testDNSServiceServer)(nil)

// GetRateLimitSettings implements the [backendpb.RateLimitServiceServer]
// interface for *testRateLimitServiceServer.
func (s *testRateLimitServiceServer) GetRateLimitSettings(
	ctx context.Context,
	req *backendpb.RateLimitSettingsRequest,
) (resp *backendpb.RateLimitSettingsResponse, err error) {
	return s.OnGetRateLimitSettings(ctx, req)
}

func TestRateLimiter_Refresh(t *testing.T) {
	var (
		allowedIP    = netip.MustParseAddr("1.2.3.4")
		notAllowedIP = netip.MustParseAddr("4.3.2.1")

		cidr = &backendpb.CidrRange{
			Address: allowedIP.AsSlice(),
			Prefix:  32,
		}
	)

	srv := &testRateLimitServiceServer{
		OnGetRateLimitSettings: func(
			ctx context.Context,
			req *backendpb.RateLimitSettingsRequest,
		) (resp *backendpb.RateLimitSettingsResponse, err error) {
			return &backendpb.RateLimitSettingsResponse{
				AllowedSubnets: []*backendpb.CidrRange{cidr},
			}, nil
		},
	}

	ln, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(1*time.Second),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterRateLimitServiceServer(grpcSrv, srv)

	go func() {
		pt := testutil.PanicT{}

		srvErr := grpcSrv.Serve(ln)
		require.NoError(pt, srvErr)
	}()
	t.Cleanup(grpcSrv.GracefulStop)

	allowlist := ratelimit.NewDynamicAllowlist(nil, nil)
	l, err := backendpb.NewRateLimiter(&backendpb.RateLimiterConfig{
		Logger:      backendpb.TestLogger,
		Metrics:     consul.EmptyMetrics{},
		GRPCMetrics: backendpb.EmptyGRPCMetrics{},
		Allowlist:   allowlist,
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   ln.Addr().String(),
		},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err = l.Refresh(ctx)
	require.NoError(t, err)

	ok, err := allowlist.IsAllowed(ctx, allowedIP)
	require.NoError(t, err)

	assert.True(t, ok)

	ok, err = allowlist.IsAllowed(ctx, notAllowedIP)
	require.NoError(t, err)

	assert.False(t, ok)
}
