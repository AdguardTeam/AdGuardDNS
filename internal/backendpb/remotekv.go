package backendpb

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/errors"
	"google.golang.org/protobuf/types/known/durationpb"
)

// RemoteKVConfig is the configuration for the business logic backend key-value
// storage.
type RemoteKVConfig struct {
	// Metrics is used for the collection of the backend remote key-value
	// storage statistics.
	Metrics RemoteKVMetrics

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".
	Endpoint *url.URL

	// APIKey is the API key used for authentication, if any.
	APIKey string

	// TTL is the TTL of the values in the storage.
	TTL time.Duration
}

// RemoteKV is the implementation of the [remotekv.Interface] interface that
// uses the business logic backend as the key-value storage.  It is safe for
// concurrent use.
type RemoteKV struct {
	grpcMetrics GRPCMetrics
	metrics     RemoteKVMetrics
	client      RemoteKVServiceClient
	apiKey      string
	ttl         time.Duration
}

// NewRemoteKV returns a new [RemoteKV] that retrieves information from the
// business logic backend.
func NewRemoteKV(c *RemoteKVConfig) (kv *RemoteKV, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &RemoteKV{
		grpcMetrics: c.GRPCMetrics,
		metrics:     c.Metrics,
		client:      NewRemoteKVServiceClient(client),
		apiKey:      c.APIKey,
		ttl:         c.TTL,
	}, nil
}

// type check
var _ remotekv.Interface = (*RemoteKV)(nil)

// Get implements the [remotekv.Interface] interface for *RemoteKV.
func (kv *RemoteKV) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	req := &RemoteKVGetRequest{
		Key: key,
	}

	ctx = ctxWithAuthentication(ctx, kv.apiKey)

	start := time.Now()
	resp, err := kv.client.Get(ctx, req)
	if err != nil {
		err = fmt.Errorf("getting %q key: %w", key, fixGRPCError(ctx, kv.grpcMetrics, err))

		return nil, false, err
	}

	kv.metrics.ObserveOperation(ctx, RemoteKVOpGet, time.Since(start))

	defer func() { kv.metrics.IncrementLookups(ctx, ok) }()

	received := resp.GetValue()

	switch received := received.(type) {
	case *RemoteKVGetResponse_Data:
		return received.Data, true, nil
	case *RemoteKVGetResponse_Empty:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf(
			"getting %q key: response type: %w: %T(%[3]v)",
			key,
			errors.ErrBadEnumValue,
			received,
		)
	}
}

// Set implements the [remotekv.Interface] interface for *RemoteKV.
func (kv *RemoteKV) Set(ctx context.Context, key string, val []byte) (err error) {
	req := &RemoteKVSetRequest{
		Key:  key,
		Data: val,
		Ttl:  durationpb.New(kv.ttl),
	}

	ctx = ctxWithAuthentication(ctx, kv.apiKey)

	start := time.Now()
	_, err = kv.client.Set(ctx, req)
	if err != nil {
		return fmt.Errorf("setting %q key: %w", key, fixGRPCError(ctx, kv.grpcMetrics, err))
	}

	kv.metrics.ObserveOperation(ctx, RemoteKVOpSet, time.Since(start))

	return nil
}
