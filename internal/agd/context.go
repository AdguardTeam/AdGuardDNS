package agd

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
)

// Common Context Helpers

// ctxKey is the type for all common context keys.
type ctxKey uint8

const (
	ctxKeyReqID ctxKey = iota
	ctxKeyReqInfo
)

// type check
var _ fmt.Stringer = ctxKey(0)

// String implements the fmt.Stringer interface for ctxKey.
func (k ctxKey) String() (s string) {
	switch k {
	case ctxKeyReqID:
		return "ctxKeyReqID"
	case ctxKeyReqInfo:
		return "ctxKeyReqInfo"
	default:
		panic(fmt.Errorf("bad ctx key value %d", k))
	}
}

// panicBadType is a helper that panics with a message about the context key and
// the expected type.
func panicBadType(key ctxKey, v any) {
	panic(fmt.Errorf("bad type for %s: %T(%[2]v)", key, v))
}

// WithRequestID returns a copy of the parent context with the request ID added.
func WithRequestID(parent context.Context, id RequestID) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyReqID, id)
}

// RequestIDFromContext returns the request ID from the context, if any.
func RequestIDFromContext(ctx context.Context) (id RequestID, ok bool) {
	const key = ctxKeyReqID
	v := ctx.Value(key)
	if v == nil {
		return "", false
	}

	id, ok = v.(RequestID)
	if !ok {
		panicBadType(key, v)
	}

	return id, true
}

// RequestInfo contains information about the current request.  A RequestInfo
// put into the context must not be modified.
type RequestInfo struct {
	// Device is the found device.  It is nil for anonymous requests.  If Device
	// is present then Profile is also present.
	Device *Device

	// Profile is the found profile.  It is nil for anonymous requests.  If
	// Profile is present then Device is also present.
	Profile *Profile

	// Location is the GeoIP location data about the remote IP address, if any.
	Location *Location

	// ECS contains the EDNS Client Subnet option information of the request, if
	// any.
	ECS *ECS

	// FilteringGroup is the server's default filtering group.
	FilteringGroup *FilteringGroup

	// Messages is the message constructor to be used for the filtered responses
	// to this request.
	Messages *dnsmsg.Constructor

	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// ServerGroup is the name of the server group which handles this request.
	ServerGroup ServerGroupName

	// Server is the name of the server which handles this request.
	Server ServerName

	// ID is the unique ID of the request.  It is resurfaced here to optimize
	// context lookups.
	ID RequestID

	// Host is the lowercased, non-FQDN version of the hostname from the
	// question of the request.
	Host string

	// QType is the type of question for this request.
	QType dnsmsg.RRType

	// QClass is the class of question for this request.
	//
	// TODO(a.garipov): Use more.
	QClass dnsmsg.Class
}

// ECS is the content of the EDNS Client Subnet option of a DNS message.
//
// See https://datatracker.ietf.org/doc/html/rfc7871#section-6.
type ECS struct {
	// Location is the GeoIP location data about the IP address from the
	// request's ECS data, if any.
	Location *Location

	// Subnet is the source subnet.
	Subnet netip.Prefix

	// Scope is the scope prefix.
	Scope uint8
}

// ContextWithRequestInfo returns a copy of the parent context with the request
// and server group information added.  ri must not be modified after calling
// ContextWithRequestInfo.
func ContextWithRequestInfo(parent context.Context, ri *RequestInfo) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyReqInfo, ri)
}

// RequestInfoFromContext returns the request information from the context, if
// any.  ri must not be modified.
func RequestInfoFromContext(ctx context.Context) (ri *RequestInfo, ok bool) {
	const key = ctxKeyReqInfo
	v := ctx.Value(ctxKeyReqInfo)
	if v == nil {
		return nil, false
	}

	ri, ok = v.(*RequestInfo)
	if !ok {
		panicBadType(key, v)
	}

	return ri, true
}

// MustRequestInfoFromContext is a helper that wraps a call to
// RequestInfoFromContext and panics if the request information isn't in the
// context.  ri must not be modified.
func MustRequestInfoFromContext(ctx context.Context) (ri *RequestInfo) {
	ri, ok := RequestInfoFromContext(ctx)
	if !ok {
		panic(errors.Error("no request info in context"))
	}

	return ri
}
