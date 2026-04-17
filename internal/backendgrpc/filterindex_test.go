package backendgrpc_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestFilterIndexStorage_Typosquatting(t *testing.T) {
	t.Parallel()

	srv := &testFilterIndexServiceServer{
		OnGetTyposquattingFilterIndex: func(
			ctx context.Context,
			_ *dnspb.TyposquattingFilterIndexRequest,
		) (resp *dnspb.TyposquattingFilterIndexResponse, err error) {
			return &dnspb.TyposquattingFilterIndexResponse{
				Index: backendtest.TyposquattingIndexGRPC,
			}, nil
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterFilterIndexServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	storage, err := backendgrpc.NewFilterIndexStorage(&backendgrpc.FilterIndexStorageConfig{
		Logger:           slogutil.NewDiscardLogger(),
		Endpoint:         endpoint,
		GRPCMetrics:      backendgrpc.EmptyGRPCMetrics{},
		Metrics:          backendgrpc.EmptyFilterIndexStorageMetrics{},
		PublicSuffixList: publicsuffix.List,
		Clock:            timeutil.SystemClock{},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	got, err := storage.Typosquatting(ctx)
	require.NoError(t, err)

	assert.Equal(t, backendtest.TyposquattingIndex, got)
}
