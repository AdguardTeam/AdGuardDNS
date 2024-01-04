// Package backendpb contains the protobuf structures for the backend API.
package backendpb

import (
	"context"
	"fmt"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// newClient returns new properly initialized DNSServiceClient.
func newClient(apiURL *url.URL) (client DNSServiceClient, err error) {
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

	conn, err := grpc.Dial(apiURL.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}

	// Immediately make a connection attempt, since the constructor is often
	// called right before the initial refresh.
	conn.Connect()

	return NewDNSServiceClient(conn), nil
}

// reportf is a helper method for reporting non-critical errors.
func reportf(ctx context.Context, errColl errcoll.Interface, format string, args ...any) {
	errcoll.Collectf(ctx, errColl, "backendpb: "+format, args...)
}
