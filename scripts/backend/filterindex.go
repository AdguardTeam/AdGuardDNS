package main

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/httphdr"
	"google.golang.org/grpc/metadata"
)

// mockFilterIndexServiceServer is the mock [dnspb.FilterIndexServiceServer].
type mockFilterIndexServiceServer struct {
	dnspb.UnimplementedFilterIndexServiceServer
	log *slog.Logger
}

// newMockFilterIndexServiceServer creates a new instance of
// *mockFilterIndexServiceServer.
func newMockFilterIndexServiceServer(log *slog.Logger) (srv *mockFilterIndexServiceServer) {
	return &mockFilterIndexServiceServer{
		log: log,
	}
}

// type check
var _ dnspb.FilterIndexServiceServer = (*mockFilterIndexServiceServer)(nil)

// Domains protected by the typosquatting filter.
const (
	typosquattingDomain    = "protected.example"
	typosquattingDomainExc = "protecter.example"
)

// GetTyposquattingFilterIndex implements the [dnspb.FilterIndexServiceServer]
// interface for *mockFilterIndexServiceServer.
func (s *mockFilterIndexServiceServer) GetTyposquattingFilterIndex(
	ctx context.Context,
	req *dnspb.TyposquattingFilterIndexRequest,
) (resp *dnspb.TyposquattingFilterIndexResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &dnspb.TyposquattingFilterIndexResponse{
		Index: &dnspb.TyposquattingFilterIndex{
			Domains: []*dnspb.TyposquattingFilterIndex_ProtectedDomain{{
				Domain:   typosquattingDomain,
				Distance: 1,
			}},
			Exceptions: []*dnspb.TyposquattingFilterIndex_Exception{{
				Domain: typosquattingDomainExc,
			}},
		},
	}, nil
}

// Domains protected by the homoglyph filter.
const (
	homoglyphDomain = "protected.example"

	// homoglyphDomainExc has a Cyrillic "o" letter instead of the Latin one.
	homoglyphDomainExc = "prоtected.example"
)

// GetHomoglyphFilterIndex implements the [dnspb.FilterIndexServiceServer]
// interface for *mockFilterIndexServiceServer.
func (s *mockFilterIndexServiceServer) GetHomoglyphFilterIndex(
	ctx context.Context,
	req *dnspb.HomoglyphFilterIndexRequest,
) (resp *dnspb.HomoglyphFilterIndexResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	return &dnspb.HomoglyphFilterIndexResponse{
		Index: &dnspb.HomoglyphFilterIndex{
			Domains: []*dnspb.HomoglyphFilterIndex_ProtectedDomain{{
				Domain: homoglyphDomain,
			}},
			Exceptions: []*dnspb.HomoglyphFilterIndex_Exception{{
				Domain: homoglyphDomainExc,
			}},
		},
	}, nil
}
