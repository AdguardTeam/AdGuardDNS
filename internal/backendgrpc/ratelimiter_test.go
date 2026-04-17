package backendgrpc_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
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

		cidr = &dnspb.CidrRange{
			Address: allowedIP.AsSlice(),
			Prefix:  32,
		}
	)

	srv := &testRateLimitServiceServer{
		OnGetRateLimitSettings: func(
			ctx context.Context,
			req *dnspb.RateLimitSettingsRequest,
		) (resp *dnspb.RateLimitSettingsResponse, err error) {
			return &dnspb.RateLimitSettingsResponse{
				AllowedSubnets: []*dnspb.CidrRange{cidr},
			}, nil
		},
		// TODO(e.burkov):  Use and test.
		OnGetGlobalAccessSettings: func(
			ctx context.Context,
			req *dnspb.GlobalAccessSettingsRequest,
		) (resp *dnspb.GlobalAccessSettingsResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterRateLimitServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	allowlist := ratelimit.NewDynamicAllowlist(nil, nil)
	l, err := backendgrpc.NewRateLimiter(&backendgrpc.RateLimiterConfig{
		Logger:      backendtest.Logger,
		Metrics:     consul.EmptyMetrics{},
		GRPCMetrics: backendgrpc.EmptyGRPCMetrics{},
		Allowlist:   allowlist,
		Endpoint:    endpoint,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	err = l.Refresh(ctx)
	require.NoError(t, err)

	ok, err := allowlist.IsAllowed(ctx, allowedIP)
	require.NoError(t, err)

	assert.True(t, ok)

	ok, err = allowlist.IsAllowed(ctx, notAllowedIP)
	require.NoError(t, err)

	assert.False(t, ok)
}
