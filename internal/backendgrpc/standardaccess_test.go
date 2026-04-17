package backendgrpc_test

import (
	"cmp"
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testAddr is test IPv4 address for tests.
var testAddr = netip.MustParseAddr("192.0.2.0")

func TestStandardAccess_Config(t *testing.T) {
	t.Parallel()

	respCh := make(chan *dnspb.GlobalAccessSettingsResponse, 1)
	errCh := make(chan error, 1)

	srv := newTestRateLimitServer(t, newTestOnGetGlobalSettings(t, respCh, errCh), nil)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterRateLimitServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	stdAccess := newTestStandardAccess(t, &backendgrpc.StandardAccessConfig{
		Endpoint: endpoint,
	})
	require.True(t, t.Run("success", func(t *testing.T) {
		accessSettings := &dnspb.AccessSettings{
			AllowlistCidr: []*dnspb.CidrRange{{
				Address: testAddr.AsSlice(),
				Prefix:  8,
			}},
			BlocklistCidr: []*dnspb.CidrRange{{
				Address: testAddr.AsSlice(),
				Prefix:  16,
			}},
			AllowlistAsn:         []uint32{backendtest.ASNAllowed},
			BlocklistAsn:         []uint32{backendtest.ASNBlocked},
			BlocklistDomainRules: []string{backendtest.BlocklistDomainRule},
			Enabled:              true,
		}

		resp := &dnspb.GlobalAccessSettingsResponse{
			Standard: accessSettings,
		}

		testutil.RequireSend(t, respCh, resp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		okBlockerC := newTestBlockerConfig(t)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		var c *access.StandardBlockerConfig
		var err error
		c, err = stdAccess.Config(ctx)
		require.NoError(t, err)

		assert.Equal(t, okBlockerC, c)
	}))

	require.True(t, t.Run("grpc_error", func(t *testing.T) {
		const wantErrMsg = `loading global access settings: rpc error: code = Unknown desc = ` +
			`assert.AnError general error for testing`

		testutil.RequireSend(t, respCh, nil, backendtest.Timeout)
		testutil.RequireSend(t, errCh, assert.AnError, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		var c *access.StandardBlockerConfig
		var err error
		c, err = stdAccess.Config(ctx)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, c)
	}))
}

func TestStandardAccess_Config_malformed(t *testing.T) {
	t.Parallel()

	wantErrMsgFromColl := "converting cidrs: bad cidr at index 0: [49 50 51]"

	errColl := &agdtest.ErrorCollector{}
	errColl.OnCollect = func(_ context.Context, err error) {
		testutil.AssertErrorMsg(t, wantErrMsgFromColl, err)
	}

	as := &dnspb.AccessSettings{
		AllowlistCidr: []*dnspb.CidrRange{{
			Address: []byte("123"),
			Prefix:  8,
		}},
		BlocklistCidr: []*dnspb.CidrRange{{
			Address: testAddr.AsSlice(),
			Prefix:  16,
		}},
		AllowlistAsn:         []uint32{backendtest.ASNAllowed},
		BlocklistAsn:         []uint32{backendtest.ASNBlocked},
		BlocklistDomainRules: []string{backendtest.BlocklistDomainRule},
		Enabled:              true,
	}

	wantResp := &dnspb.GlobalAccessSettingsResponse{
		Standard: as,
	}

	onGetGlobalAccessSettings := func(
		_ context.Context,
		_ *dnspb.GlobalAccessSettingsRequest,
	) (resp *dnspb.GlobalAccessSettingsResponse, err error) {
		return wantResp, nil
	}

	srv := newTestRateLimitServer(t, onGetGlobalAccessSettings, nil)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterRateLimitServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	stdAccess := newTestStandardAccess(t, &backendgrpc.StandardAccessConfig{
		Endpoint: endpoint,
		ErrColl:  errColl,
	})

	okBlockerC := newTestBlockerConfig(t)
	okBlockerC.AllowedNets = nil

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	var c *access.StandardBlockerConfig
	var err error
	c, err = stdAccess.Config(ctx)
	require.NoError(t, err)

	assert.Equal(t, okBlockerC, c)
}

// newTestRateLimitServer creates a new instance of
// [dnspb.RateLimitServiceServer] with the provided handlers for tests.  If one
// of the handlers is nil, then the call of it is estimated as unexpected.
func newTestRateLimitServer(
	tb testing.TB,
	onGetGlobalAccessSettings func(
		_ context.Context,
		_ *dnspb.GlobalAccessSettingsRequest,
	) (resp *dnspb.GlobalAccessSettingsResponse, err error),
	onGetRateLimitSettings func(
		_ context.Context,
		req *dnspb.RateLimitSettingsRequest,
	) (resp *dnspb.RateLimitSettingsResponse, err error),
) (s dnspb.RateLimitServiceServer) {
	tb.Helper()

	if onGetGlobalAccessSettings == nil {
		onGetGlobalAccessSettings = func(
			ctx context.Context,
			req *dnspb.GlobalAccessSettingsRequest,
		) (resp *dnspb.GlobalAccessSettingsResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		}
	}

	if onGetRateLimitSettings == nil {
		onGetRateLimitSettings = func(
			ctx context.Context,
			req *dnspb.RateLimitSettingsRequest,
		) (resp *dnspb.RateLimitSettingsResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		}
	}

	return &testRateLimitServiceServer{
		OnGetRateLimitSettings:    onGetRateLimitSettings,
		OnGetGlobalAccessSettings: onGetGlobalAccessSettings,
	}
}

// newTestOnGetGlobalSettings creates a new OnGetGlobalAccessSettings handler
// for tests.  respCh and errCh must not be nil.
func newTestOnGetGlobalSettings(
	tb testing.TB,
	respCh chan *dnspb.GlobalAccessSettingsResponse,
	errCh chan error,
) (h func(
	_ context.Context,
	_ *dnspb.GlobalAccessSettingsRequest,
) (resp *dnspb.GlobalAccessSettingsResponse, err error),
) {
	tb.Helper()

	return func(
		_ context.Context,
		_ *dnspb.GlobalAccessSettingsRequest,
	) (resp *dnspb.GlobalAccessSettingsResponse, err error) {
		pt := testutil.NewPanicT(tb)

		resp, ok := testutil.RequireReceive(pt, respCh, backendtest.Timeout)
		require.True(pt, ok)

		err, ok = testutil.RequireReceive(pt, errCh, backendtest.Timeout)
		require.True(pt, ok)

		return resp, err
	}
}

// newOkBlockerConfig creates a new instance of *access.StandardBlockerConfig
// with test values.
func newTestBlockerConfig(tb testing.TB) (c *access.StandardBlockerConfig) {
	tb.Helper()

	return &access.StandardBlockerConfig{
		AllowedNets: []netip.Prefix{
			netip.PrefixFrom(testAddr, 8),
		},
		BlockedNets: []netip.Prefix{
			netip.PrefixFrom(testAddr, 16),
		},
		AllowedASN:           []geoip.ASN{backendtest.ASNAllowed},
		BlockedASN:           []geoip.ASN{backendtest.ASNBlocked},
		BlocklistDomainRules: []string{backendtest.BlocklistDomainRule},
	}
}

// newTestStandardAccess is a helper for creating the
// *backendgrpc.StandardAccess for tests.  c may not be nil, and all zero-values
// fields in c are replaced with defaults for tests.
func newTestStandardAccess(
	tb testing.TB,
	c *backendgrpc.StandardAccessConfig,
) (sa *backendgrpc.StandardAccess) {
	tb.Helper()

	c = cmp.Or(c, &backendgrpc.StandardAccessConfig{})

	c.Logger = cmp.Or(c.Logger, backendtest.Logger)

	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, backendtest.ErrColl)
	c.GRPCMetrics = cmp.Or[backendgrpc.GRPCMetrics](c.GRPCMetrics, backendgrpc.EmptyGRPCMetrics{})
	c.Metrics = cmp.Or[backendgrpc.StandardAccessMetrics](
		c.Metrics,
		backendgrpc.EmptyStandardAccessMetrics{},
	)
	c.APIKey = cmp.Or(c.APIKey)
	c.Endpoint = cmp.Or(c.Endpoint)

	stdAccess, err := backendgrpc.NewStandardAccess(c)
	require.NoError(tb, err)

	return stdAccess
}
