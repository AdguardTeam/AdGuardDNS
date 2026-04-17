package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/patrickmn/go-cache"
	"google.golang.org/grpc/metadata"
)

// mockRemoteKVServiceServer is the mock [dnspb.RemoteKVServiceServer].
type mockRemoteKVServiceServer struct {
	dnspb.UnimplementedRemoteKVServiceServer
	log  *slog.Logger
	strg *cache.Cache
}

// newMockRemoteKVServiceServer creates a new instance of
// *mockRemoteKVServiceServer.
func newMockRemoteKVServiceServer(log *slog.Logger) (srv *mockRemoteKVServiceServer) {
	const (
		defaultCacheExp = 30 * time.Second
		defaultCacheGC  = 1 * time.Minute
	)

	return &mockRemoteKVServiceServer{
		log:  log,
		strg: cache.New(defaultCacheExp, defaultCacheGC),
	}
}

// type check
var _ dnspb.RemoteKVServiceServer = (*mockRemoteKVServiceServer)(nil)

// Get implements the [dnspb.RemoteKVServiceServer] interface for
// *mockRemoteKVServiceServer.
func (s *mockRemoteKVServiceServer) Get(
	ctx context.Context,
	req *dnspb.RemoteKVGetRequest,
) (resp *dnspb.RemoteKVGetResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	resp = &dnspb.RemoteKVGetResponse{
		Value: &dnspb.RemoteKVGetResponse_Empty{},
	}

	val, ok := s.strg.Get(req.Key)
	if ok {
		resp.Value = &dnspb.RemoteKVGetResponse_Data{
			Data: val.([]byte),
		}
	}

	return resp, nil
}

// Set implements the [dnspb.RemoteKVServiceServer] interface for
// *mockRemoteKVServiceServer.
func (s *mockRemoteKVServiceServer) Set(
	ctx context.Context,
	req *dnspb.RemoteKVSetRequest,
) (resp *dnspb.RemoteKVSetResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"setting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	s.strg.Set(req.Key, req.Data, req.Ttl.AsDuration())

	return &dnspb.RemoteKVSetResponse{}, err
}
