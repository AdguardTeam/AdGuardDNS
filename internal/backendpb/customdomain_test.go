package backendpb_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testCustomDomainServiceServer is the [backendpb.CustomDomainServiceServer] for
// tests.
type testCustomDomainServiceServer struct {
	backendpb.UnimplementedCustomDomainServiceServer

	OnGetCustomDomainCertificate func(
		ctx context.Context,
		req *backendpb.CustomDomainCertificateRequest,
	) (resp *backendpb.CustomDomainCertificateResponse, err error)
}

// type check
var _ backendpb.CustomDomainServiceServer = (*testCustomDomainServiceServer)(nil)

// GetCustomDomainCertificate implements the
// [backendpb.CustomDomainServiceServer] interface for
// *testCustomDomainServiceServer.
func (s *testCustomDomainServiceServer) GetCustomDomainCertificate(
	ctx context.Context,
	req *backendpb.CustomDomainCertificateRequest,
) (resp *backendpb.CustomDomainCertificateResponse, err error) {
	return s.OnGetCustomDomainCertificate(ctx, req)
}

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
			req *backendpb.CustomDomainCertificateRequest,
		) (resp *backendpb.CustomDomainCertificateResponse, err error) {
			pt := testutil.PanicT{}
			require.NotNil(pt, req)
			require.Equal(pt, certName, req.CertName)

			return &backendpb.CustomDomainCertificateResponse{
				Certificate: certData,
				PrivateKey:  pkeyData,
			}, nil
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendpb.TestTimeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterCustomDomainServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	s, err := backendpb.NewCustomDomainStorage(&backendpb.CustomDomainStorageConfig{
		Endpoint:    endpoint,
		Logger:      backendpb.TestLogger,
		Clock:       timeutil.SystemClock{},
		GRPCMetrics: backendpb.EmptyGRPCMetrics{},
		Metrics:     backendpb.EmptyCustomDomainStorageMetrics{},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)
	gotCertData, gotPKeyData, err := s.CertificateData(ctx, certName)
	require.NoError(t, err)

	assert.Equal(t, certData, gotCertData)
	assert.Equal(t, pkeyData, gotPKeyData)
}
