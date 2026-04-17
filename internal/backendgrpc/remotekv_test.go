package backendgrpc_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestRemoteKV_Get(t *testing.T) {
	const testTTL = 10 * time.Second

	pt := &testutil.PanicT{}

	strg := map[string][]byte{}
	srv := &testRemoteKVServiceServer{
		OnGet: func(
			ctx context.Context,
			req *dnspb.RemoteKVGetRequest,
		) (resp *dnspb.RemoteKVGetResponse, err error) {
			resp = &dnspb.RemoteKVGetResponse{
				Value: &dnspb.RemoteKVGetResponse_Empty{},
			}

			if val, ok := strg[req.Key]; ok {
				resp.Value = &dnspb.RemoteKVGetResponse_Data{Data: val}
			}

			return resp, nil
		},

		OnSet: func(
			ctx context.Context,
			req *dnspb.RemoteKVSetRequest,
		) (resp *dnspb.RemoteKVSetResponse, err error) {
			require.Equal(pt, testTTL, req.Ttl.AsDuration())

			strg[req.Key] = req.Data

			return &dnspb.RemoteKVSetResponse{}, nil
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterRemoteKVServiceServer(grpcSrv, srv)

	endpoint := runLocalGRPCServer(t, grpcSrv)

	kv, err := backendgrpc.NewRemoteKV(&backendgrpc.RemoteKVConfig{
		GRPCMetrics: backendgrpc.EmptyGRPCMetrics{},
		Metrics:     backendgrpc.EmptyRemoteKVMetrics{},
		Endpoint:    endpoint,
		APIKey:      "apikey",
		TTL:         testTTL,
	})
	require.NoError(t, err)

	const (
		keyWithData = "key"
		keyNoData   = "unknown"
	)

	t.Run("success", func(t *testing.T) {
		val := []byte("value")
		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)

		setErr := kv.Set(ctx, keyWithData, val)
		require.NoError(t, setErr)

		gotVal, ok, getErr := kv.Get(ctx, keyWithData)
		require.NoError(t, getErr)
		require.True(t, ok)

		assert.Equal(t, val, gotVal)
	})

	t.Run("not_found", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)

		val, ok, getErr := kv.Get(ctx, keyNoData)
		require.NoError(t, getErr)
		require.False(t, ok)

		assert.Nil(t, val)
	})
}
