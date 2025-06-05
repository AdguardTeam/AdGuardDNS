package backendpb_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
		// TODO(e.burkov):  Use and test.
		OnGetGlobalAccessSettings: func(
			_ context.Context,
			_ *backendpb.GlobalAccessSettingsRequest,
		) (_ *backendpb.GlobalAccessSettingsResponse, _ error) {
			panic(fmt.Errorf("unexpected call to GetGlobalAccessSettings"))
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendpb.TestTimeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterRateLimitServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	allowlist := ratelimit.NewDynamicAllowlist(nil, nil)
	l, err := backendpb.NewRateLimiter(&backendpb.RateLimiterConfig{
		Logger:      backendpb.TestLogger,
		Metrics:     consul.EmptyMetrics{},
		GRPCMetrics: backendpb.EmptyGRPCMetrics{},
		Allowlist:   allowlist,
		Endpoint:    endpoint,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)
	err = l.Refresh(ctx)
	require.NoError(t, err)

	ok, err := allowlist.IsAllowed(ctx, allowedIP)
	require.NoError(t, err)

	assert.True(t, ok)

	ok, err = allowlist.IsAllowed(ctx, notAllowedIP)
	require.NoError(t, err)

	assert.False(t, ok)
}
