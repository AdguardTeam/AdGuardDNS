package dnsservertest

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/testutil"
)

// MetricsListener is a mock implementation of the [dnsserver.MetricsListener]
// interface for tests.
type MetricsListener struct {
	OnOnRequest func(
		ctx context.Context,
		info *dnsserver.QueryInfo,
		rw dnsserver.ResponseWriter,
	)
	OnOnInvalidMsg            func(ctx context.Context)
	OnOnError                 func(ctx context.Context, err error)
	OnOnPanic                 func(ctx context.Context, v any)
	OnOnQUICAddressValidation func(hit bool)
	OnAdjustActiveRequests    func(ctx context.Context, num int)
}

// NewMetricsListener creates a new MetricsListener with all callbacks set to
// panic.
func NewMetricsListener() (ml *MetricsListener) {
	return &MetricsListener{
		OnOnRequest: func(
			ctx context.Context,
			info *dnsserver.QueryInfo,
			rw dnsserver.ResponseWriter,
		) {
			panic(testutil.UnexpectedCall(ctx, info, rw))
		},
		OnOnInvalidMsg: func(ctx context.Context) {
			panic(testutil.UnexpectedCall(ctx))
		},
		OnOnError: func(ctx context.Context, err error) {
			panic(testutil.UnexpectedCall(ctx, err))
		},
		OnOnPanic: func(ctx context.Context, v any) {
			panic(testutil.UnexpectedCall(ctx, v))
		},
		OnOnQUICAddressValidation: func(hit bool) {
			panic(testutil.UnexpectedCall(hit))
		},
		OnAdjustActiveRequests: func(ctx context.Context, num int) {
			panic(testutil.UnexpectedCall(ctx, num))
		},
	}
}

// type check
var _ dnsserver.MetricsListener = (*MetricsListener)(nil)

// OnRequest implements the [dnsserver.MetricsListener] interface for
// *MetricsListener.
func (ml *MetricsListener) OnRequest(
	ctx context.Context,
	info *dnsserver.QueryInfo,
	rw dnsserver.ResponseWriter,
) {
	ml.OnOnRequest(ctx, info, rw)
}

// OnInvalidMsg implements the [dnsserver.MetricsListener] interface for
// *MetricsListener.
func (ml *MetricsListener) OnInvalidMsg(ctx context.Context) {
	ml.OnOnInvalidMsg(ctx)
}

// OnError implements the [dnsserver.MetricsListener] interface for
// *MetricsListener.
func (ml *MetricsListener) OnError(ctx context.Context, err error) {
	ml.OnOnError(ctx, err)
}

// OnPanic implements the [dnsserver.MetricsListener] interface for
// *MetricsListener.
func (ml *MetricsListener) OnPanic(ctx context.Context, v any) {
	ml.OnOnPanic(ctx, v)
}

// OnQUICAddressValidation implements the [dnsserver.MetricsListener] interface
// for *MetricsListener.
func (ml *MetricsListener) OnQUICAddressValidation(hit bool) {
	ml.OnOnQUICAddressValidation(hit)
}

// AdjustActiveRequests implements the [dnsserver.MetricsListener] interface for
// *MetricsListener.
func (ml *MetricsListener) AdjustActiveRequests(ctx context.Context, num int) {
	ml.OnAdjustActiveRequests(ctx, num)
}
