package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/patrickmn/go-cache"
	"google.golang.org/grpc/metadata"
)

// mockRemoteKVServiceServer is the mock [backendpb.RemoteKVServiceServer].
type mockRemoteKVServiceServer struct {
	backendpb.UnimplementedRemoteKVServiceServer
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
var _ backendpb.RemoteKVServiceServer = (*mockRemoteKVServiceServer)(nil)

// Get implements the [backendpb.RemoteKVServiceServer] interface for
// *mockRemoteKVServiceServer.
func (s *mockRemoteKVServiceServer) Get(
	ctx context.Context,
	req *backendpb.RemoteKVGetRequest,
) (resp *backendpb.RemoteKVGetResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	resp = &backendpb.RemoteKVGetResponse{
		Value: &backendpb.RemoteKVGetResponse_Empty{},
	}

	val, ok := s.strg.Get(req.Key)
	if ok {
		resp.Value = &backendpb.RemoteKVGetResponse_Data{
			Data: val.([]byte),
		}
	}

	return resp, nil
}

// Set implements the [backendpb.RemoteKVServiceServer] interface for
// *mockRemoteKVServiceServer.
func (s *mockRemoteKVServiceServer) Set(
	ctx context.Context,
	req *backendpb.RemoteKVSetRequest,
) (resp *backendpb.RemoteKVSetResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"setting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	s.strg.Set(req.Key, req.Data, req.Ttl.AsDuration())

	return &backendpb.RemoteKVSetResponse{}, err
}
