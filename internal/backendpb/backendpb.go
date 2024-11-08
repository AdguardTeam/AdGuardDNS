// Package backendpb contains the protobuf structures for the backend API.
//
// TODO(a.garipov):  Move the generated code into a separate package.
package backendpb

import (
	"context"
	"fmt"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/httphdr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// newClient returns new properly initialized gRPC connection to the API server.
func newClient(apiURL *url.URL) (client *grpc.ClientConn, err error) {
	var creds credentials.TransportCredentials
	switch s := apiURL.Scheme; s {
	case "grpc":
		creds = insecure.NewCredentials()
	case "grpcs":
		// Use a nil [tls.Config] to get the default TLS configuration.
		creds = credentials.NewTLS(nil)
	default:
		return nil, fmt.Errorf("bad grpc url scheme %q", s)
	}

	conn, err := grpc.NewClient(apiURL.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}

	// Immediately make a connection attempt, since the constructor is often
	// called right before the initial refresh.
	conn.Connect()

	return conn, nil
}

// reportf is a helper method for reporting non-critical errors.
func reportf(ctx context.Context, errColl errcoll.Interface, format string, args ...any) {
	errcoll.Collectf(ctx, errColl, "backendpb: "+format, args...)
}

// ctxWithAuthentication adds the API key authentication header to the outgoing
// request context if apiKey is not empty.  If it is empty, ctx is parent.
func ctxWithAuthentication(parent context.Context, apiKey string) (ctx context.Context) {
	ctx = parent
	if apiKey == "" {
		return ctx
	}

	// TODO(a.garipov): Better validations for the key.
	md := metadata.Pairs(httphdr.Authorization, fmt.Sprintf("Bearer %s", apiKey))

	return metadata.NewOutgoingContext(ctx, md)
}
