package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/httphdr"
	"google.golang.org/grpc/metadata"
)

// mockDNSServiceServer is the mock [backendpb.CustomDomainServiceServer].
type mockCustomDomainServiceServer struct {
	backendpb.UnimplementedCustomDomainServiceServer
	logger *slog.Logger
}

// newCustomDomainServiceServer creates a new instance of
// *mockCustomDomainServiceServer.  logger must not be nil.
func newCustomDomainServiceServer(logger *slog.Logger) (srv *mockCustomDomainServiceServer) {
	return &mockCustomDomainServiceServer{
		logger: logger,
	}
}

// type check
var _ backendpb.CustomDomainServiceServer = (*mockCustomDomainServiceServer)(nil)

// GetCustomDomainCertificate implements the
// [backendpb.CustomDomainServiceServer] interface
// for *mockCustomDomainServiceServer.
func (s *mockCustomDomainServiceServer) GetCustomDomainCertificate(
	ctx context.Context,
	req *backendpb.CustomDomainCertificateRequest,
) (resp *backendpb.CustomDomainCertificateResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.logger.InfoContext(
		ctx,
		"getting custom domain certificate",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	cert, key, err := generateCert(1)
	if err != nil {
		return nil, err
	}

	resp = &backendpb.CustomDomainCertificateResponse{
		Certificate: cert,
		PrivateKey:  x509.MarshalPKCS1PrivateKey(key),
	}

	return resp, nil
}

// generateCert is a helper function that generates certificate and key.
//
// TODO(f.setrakov): DRY logic with tlsconfig_test.newCertAndKey.
func generateCert(n int64) (certDER []byte, key *rsa.PrivateKey, err error) {
	serialNumber := big.NewInt(n)

	notBefore := time.Now().Add(-time.Hour * 24)
	notAfter := time.Now().Add(time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames: []string{
			"current-1.domain.example",
			"current-2.domain.example",
			"pending-1.domain.example",
			"pending-2.domain.example",
		},
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generating rsa key: %w", err)
	}

	cer, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}

	return cer, key, nil
}
