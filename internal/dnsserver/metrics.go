package dnsserver

import (
	"context"

	"github.com/miekg/dns"
)

// MetricsListener is an interface that is used for monitoring a server's state.
// The dnsserver package user may supply MetricsListener implementation that
// would increment different kinds of metrics (for instance, prometheus
// metrics).
//
// Every function accepts context.Context as a parameter. This context must have
// server information attached to it.  It can be retrieved using functions
// [ServerInfoFromContext] or [MustServerInfoFromContext].
//
// NOTE: Implementations must be thread-safe.
type MetricsListener interface {
	// OnRequest called when we finished processing a request, and we know what
	// response has been written.
	//
	// ctx is the context of the DNS request.  Besides the server info, it also
	// must contain request info (retrieved by [MustRequestInfoFromContext]).
	//
	// info contains DNS request and response data. rw is the [ResponseWriter]
	// that was used to write the response.
	//
	// Note, that if the request was discarded (BadFormat or NotImplemented)
	// this method will still be called so the request message may be incorrect
	// (i.e. no Question section or whatever).
	OnRequest(ctx context.Context, info *QueryInfo, rw ResponseWriter)

	// OnInvalidMsg called when the server encounters an invalid DNS message.
	// It may be simply crap bytes that cannot be unpacked or a message that the
	// server cannot accept (i.e. request with a "response" flag, etc). ctx is
	// the context of the DNS request.
	OnInvalidMsg(ctx context.Context)

	// OnError called when any error (expected or unexpected) happened. Besides
	// incrementing metrics it can also be used for error reporting. ctx is the
	// context of the DNS request.
	OnError(ctx context.Context, err error)

	// OnPanic called when a panic happened in a goroutine. ctx is the context
	// of the DNS request.  v is the object returned by the recover() method.
	OnPanic(ctx context.Context, v any)

	// OnQUICAddressValidation called when a QUIC connection needs to determine
	// whether it's required or not to send the retry packet.  This metric
	// allows to keep an eye on how the addresses cache performs.
	// TODO(ameshkov): find a way to attach this info to ctx and remove this.
	OnQUICAddressValidation(hit bool)
}

// QueryInfo contains the request with its size, and the response with its size.
type QueryInfo struct {
	// Request is the DNS request.
	Request *dns.Msg

	// Response is the DNS response.  The response will always be present.
	Response *dns.Msg

	// Request size is the size of DNS request in bytes.
	RequestSize int

	// ResponseSize is the size of DNS response in bytes.  May be 0 if no
	// response was sent.
	ResponseSize int
}

// EmptyMetricsListener implements [MetricsListener] with empty functions.  This
// implementation is used by default if the user does not supply a custom one.
type EmptyMetricsListener struct{}

// type check
var _ MetricsListener = EmptyMetricsListener{}

// OnRequest implements the [MetricsListener] interface for
// EmptyMetricsListener.
func (e EmptyMetricsListener) OnRequest(_ context.Context, _ *QueryInfo, _ ResponseWriter) {}

// OnInvalidMsg implements the [MetricsListener] interface for
// EmptyMetricsListener.
func (e EmptyMetricsListener) OnInvalidMsg(_ context.Context) {}

// OnError implements the [MetricsListener] interface for EmptyMetricsListener.
func (e EmptyMetricsListener) OnError(_ context.Context, _ error) {}

// OnPanic implements the [MetricsListener] interface for EmptyMetricsListener.
func (e EmptyMetricsListener) OnPanic(_ context.Context, _ any) {}

// OnQUICAddressValidation implements the [MetricsListener] interface for
// EmptyMetricsListener.
func (e EmptyMetricsListener) OnQUICAddressValidation(_ bool) {}
