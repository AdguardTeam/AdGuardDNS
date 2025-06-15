// main implements a single mock GRPC server for backend services defined by
// BILLSTAT_URL, PROFILES_URL, and REMOTE_KV_URL environment variables.
package main

import (
	"net"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
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
	backendpb.RegisterDNSServiceServer(grpcSrv, dnsSrv)

	kvSrv := newMockRemoteKVServiceServer(l.With(slogutil.KeyPrefix, "remote_kv"))
	backendpb.RegisterRemoteKVServiceServer(grpcSrv, kvSrv)

	rateLimitSrv := newMockRateLimitServiceServer(l.With(slogutil.KeyPrefix, "rate_limiter"))
	backendpb.RegisterRateLimitServiceServer(grpcSrv, rateLimitSrv)

	sessTickSrv := newMockSessionTicketServiceServer(l.With(slogutil.KeyPrefix, "session_ticket"))
	backendpb.RegisterSessionTicketServiceServer(grpcSrv, sessTickSrv)

	l.Info("starting serving", "laddr", listenAddr)
	err = grpcSrv.Serve(lsnr)
	if err != nil {
		l.Error("serving grpc", slogutil.KeyError, err)

		os.Exit(osutil.ExitCodeFailure)
	}
}
