package backendpb

import (
	"context"
	"time"
)

// GRPCError is a type alias for string that contains the gRPC error type.
//
// See [GRPCMetrics.IncrementErrorCount].
//
// TODO(s.chzhen):  Rewrite as soon as the import cycle is resolved.
type GRPCError = string

// gRPC errors of [GRPCError] type.
//
// NOTE:  Keep in sync with [metrics.GRPCError].
const (
	GRPCErrAuthentication GRPCError = "auth"
	GRPCErrBadRequest     GRPCError = "bad_req"
	GRPCErrDeviceQuota    GRPCError = "dev_quota"
	GRPCErrOther          GRPCError = "other"
	GRPCErrRateLimit      GRPCError = "rate_limit"
	GRPCErrTimeout        GRPCError = "timeout"
)

// GRPCMetrics is an interface that is used for the collection of the protobuf
// communication statistics.
//
// TODO(a.garipov):  Consider adding a label indicating the source.
type GRPCMetrics interface {
	// IncrementErrorCount increments the gRPC error count of errType.  errType
	// must be one of [GRPCError] values.
	IncrementErrorCount(ctx context.Context, errType GRPCError)
}

// EmptyGRPCMetrics is the implementation of the [GRPCMetrics] interface that
// does nothing.
type EmptyGRPCMetrics struct{}

// type check
var _ GRPCMetrics = EmptyGRPCMetrics{}

// IncrementErrorCount implements the [GRPCMetrics] interface for
// EmptyGRPCMetrics.
func (EmptyGRPCMetrics) IncrementErrorCount(_ context.Context, _ GRPCError) {}

// CustomDomainStorageMetrics is an interface that is used for the collection of
// the statistics of the custom-domain storage.
type CustomDomainStorageMetrics interface {
	// ObserveRequest updates the custom-domain storage statistics.  dur must be
	// positive.
	ObserveRequest(ctx context.Context, dur time.Duration, err error)
}

// EmptyCustomDomainStorageMetrics is the implementation of the
// [CustomDomainStorageMetrics] interface that does nothing.
type EmptyCustomDomainStorageMetrics struct{}

// type check
var _ CustomDomainStorageMetrics = EmptyCustomDomainStorageMetrics{}

// ObserveRequest implements the [CustomDomainStorageMetrics] interface for
// EmptyCustomDomainStorageMetrics.
func (EmptyCustomDomainStorageMetrics) ObserveRequest(
	_ context.Context,
	_ time.Duration,
	_ error,
) {
}

// ProfileDBMetrics is an interface that is used for the collection of the
// profile database statistics.
type ProfileDBMetrics interface {
	// IncrementInvalidDevicesCount increments the number of invalid devices.
	IncrementInvalidDevicesCount(ctx context.Context)

	// UpdateStats updates profile receiving and decoding statistics.
	UpdateStats(ctx context.Context, avgRecv, avgDec time.Duration)
}

// EmptyProfileDBMetrics is the implementation of the [ProfileDBMetrics]
// interface that does nothing.
type EmptyProfileDBMetrics struct{}

// type check
var _ ProfileDBMetrics = EmptyProfileDBMetrics{}

// IncrementInvalidDevicesCount implements the [ProfileDBMetrics] interface for
// EmptyProfileDBMetrics.
func (EmptyProfileDBMetrics) IncrementInvalidDevicesCount(_ context.Context) {}

// UpdateStats implements the [ProfileDBMetrics] interface for
// EmptyProfileDBMetrics.
func (EmptyProfileDBMetrics) UpdateStats(_ context.Context, _, _ time.Duration) {}

// RemoteKVOp is the type alias for string that contains remote key-value
// storage operation name.
//
// See [RemoteKVMetrics.ObserveOperation].
type RemoteKVOp = string

// Remote key-value storage operation names for [RemoteKVOp].
//
// NOTE:  Keep in sync with [metrics.RemoteKVOp].
const (
	RemoteKVOpGet RemoteKVOp = "get"
	RemoteKVOpSet RemoteKVOp = "set"
)

// RemoteKVMetrics is an interface that is used for the collection of the remote
// key-value storage statistics.
//
// TODO(e.burkov):  It may actually describe metrics for any remote key-value
// storage implementation, consider declaring it in the [remotekv] package.
type RemoteKVMetrics interface {
	// ObserveOperation updates the remote key-value storage statistics.  op
	// must be one of [RemoteKVOp] values.
	ObserveOperation(ctx context.Context, op string, dur time.Duration)

	// IncrementLookups increments the number of lookups.  hit is true if the
	// lookup returned a value.
	IncrementLookups(ctx context.Context, hit bool)
}

// EmptyRemoteKVMetrics is the implementation of the [RemoteKVMetrics] interface
// that does nothing.
type EmptyRemoteKVMetrics struct{}

// type check
var _ RemoteKVMetrics = EmptyRemoteKVMetrics{}

// ObserveOperation implements the [RemoteKVMetrics] interface for
// EmptyRemoteKVMetrics.
func (EmptyRemoteKVMetrics) ObserveOperation(_ context.Context, _ string, _ time.Duration) {}

// IncrementLookups implements the [RemoteKVMetrics] interface for
// EmptyRemoteKVMetrics.
func (EmptyRemoteKVMetrics) IncrementLookups(_ context.Context, _ bool) {}

// TicketStorageMetrics is an interface that is used for the collection of
// session ticket storage statistics.
type TicketStorageMetrics interface {
	// SetTicketStatus sets the status of the session ticket update operation
	// for the given ticket.
	SetTicketStatus(
		ctx context.Context,
		name string,
		updTime time.Time,
		err error,
	)
}

// EmptyTicketStorageMetrics is the implementation of the [TicketStorageMetrics]
// interface that does nothing.
type EmptyTicketStorageMetrics struct{}

// type check
var _ TicketStorageMetrics = EmptyTicketStorageMetrics{}

// SetTicketStatus implements the [TicketStorageMetrics] interface for
// EmptyTicketStorageMetrics.
func (EmptyTicketStorageMetrics) SetTicketStatus(
	_ context.Context,
	_ string,
	_ time.Time,
	_ error,
) {
}
