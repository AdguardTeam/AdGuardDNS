package backendpb_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
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
			req *backendpb.RemoteKVGetRequest,
		) (resp *backendpb.RemoteKVGetResponse, err error) {
			resp = &backendpb.RemoteKVGetResponse{
				Value: &backendpb.RemoteKVGetResponse_Empty{},
			}

			if val, ok := strg[req.Key]; ok {
				resp.Value = &backendpb.RemoteKVGetResponse_Data{Data: val}
			}

			return resp, nil
		},

		OnSet: func(
			ctx context.Context,
			req *backendpb.RemoteKVSetRequest,
		) (resp *backendpb.RemoteKVSetResponse, err error) {
			require.Equal(pt, testTTL, req.Ttl.AsDuration())

			strg[req.Key] = req.Data

			return &backendpb.RemoteKVSetResponse{}, nil
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendpb.TestTimeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterRemoteKVServiceServer(grpcSrv, srv)

	endpoint := runLocalGRPCServer(t, grpcSrv)

	kv, err := backendpb.NewRemoteKV(&backendpb.RemoteKVConfig{
		GRPCMetrics: backendpb.EmptyGRPCMetrics{},
		Metrics:     backendpb.EmptyRemoteKVMetrics{},
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
		ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)

		setErr := kv.Set(ctx, keyWithData, val)
		require.NoError(t, setErr)

		gotVal, ok, getErr := kv.Get(ctx, keyWithData)
		require.NoError(t, getErr)
		require.True(t, ok)

		assert.Equal(t, val, gotVal)
	})

	t.Run("not_found", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)

		val, ok, getErr := kv.Get(ctx, keyNoData)
		require.NoError(t, getErr)
		require.False(t, ok)

		assert.Nil(t, val)
	})
}
