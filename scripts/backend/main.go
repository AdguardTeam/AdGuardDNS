// main implements a single mock GRPC server for backend services defined by
// BILLSTAT_URL, PROFILES_URL, REMOTE_KV_URL, and other environment variables.
package main

import (
	"net"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"google.golang.org/grpc"
)

func main() {
	l := slogutil.New(nil)

	const listenAddr = "localhost:6062"

	lsnr, err := net.Listen("tcp", listenAddr)
	if err != nil {
		l.Error("getting listener", slogutil.KeyError, err)

		os.Exit(osutil.ExitCodeFailure)
	}

	grpcSrv := grpc.NewServer()
	dnsSrv := newMockDNSServiceServer(l.With(slogutil.KeyPrefix, "dns"))
	dnspb.RegisterDNSServiceServer(grpcSrv, dnsSrv)

	kvSrv := newMockRemoteKVServiceServer(l.With(slogutil.KeyPrefix, "remote_kv"))
	dnspb.RegisterRemoteKVServiceServer(grpcSrv, kvSrv)

	rateLimitSrv := newMockRateLimitServiceServer(l.With(slogutil.KeyPrefix, "rate_limiter"))
	dnspb.RegisterRateLimitServiceServer(grpcSrv, rateLimitSrv)

	sessTickSrv := newMockSessionTicketServiceServer(l.With(slogutil.KeyPrefix, "session_ticket"))
	dnspb.RegisterSessionTicketServiceServer(grpcSrv, sessTickSrv)

	customDomainSrv := newCustomDomainServiceServer(l.With(slogutil.KeyPrefix, "custom_domain"))
	dnspb.RegisterCustomDomainServiceServer(grpcSrv, customDomainSrv)

	l.Info("starting serving", "laddr", listenAddr)
	err = grpcSrv.Serve(lsnr)
	if err != nil {
		l.Error("serving grpc", slogutil.KeyError, err)

		os.Exit(osutil.ExitCodeFailure)
	}
}
