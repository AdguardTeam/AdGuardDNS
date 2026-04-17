package backendgrpc_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCustomDomainStorage_CertificateData(t *testing.T) {
	const (
		certName = "user_cert_1"
	)

	var (
		certData = []byte{0x01, 0x02, 0x03, 0x04}
		pkeyData = []byte{0x05, 0x06, 0x07, 0x08}
	)

	srv := &testCustomDomainServiceServer{
		OnGetCustomDomainCertificate: func(
			ctx context.Context,
			req *dnspb.CustomDomainCertificateRequest,
		) (resp *dnspb.CustomDomainCertificateResponse, err error) {
			pt := testutil.PanicT{}
			require.NotNil(pt, req)
			require.Equal(pt, certName, req.CertName)

			return &dnspb.CustomDomainCertificateResponse{
				Certificate: certData,
				PrivateKey:  pkeyData,
			}, nil
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterCustomDomainServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	s, err := backendgrpc.NewCustomDomainStorage(&backendgrpc.CustomDomainStorageConfig{
		Endpoint:    endpoint,
		Logger:      backendtest.Logger,
		Clock:       timeutil.SystemClock{},
		GRPCMetrics: backendgrpc.EmptyGRPCMetrics{},
		Metrics:     backendgrpc.EmptyCustomDomainStorageMetrics{},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	gotCertData, gotPKeyData, err := s.CertificateData(ctx, certName)
	require.NoError(t, err)

	assert.Equal(t, certData, gotCertData)
	assert.Equal(t, pkeyData, gotPKeyData)
}
