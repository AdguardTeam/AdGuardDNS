package agd

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
)

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
		return RequestID{}, false
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
	// DeviceResult is the result of finding the device.
	DeviceResult DeviceResult

	// Location is the GeoIP location data about the remote IP address, if any.
	Location *geoip.Location

	// ECS contains the EDNS Client Subnet option information of the request, if
	// any.
	ECS *dnsmsg.ECS

	// FilteringGroup is the server's default filtering group.
	FilteringGroup *FilteringGroup

	// Messages is the message constructor to be used for the filtered responses
	// to this request.
	Messages *dnsmsg.Constructor

	// ServerGroup is the server group which handles this request.
	ServerGroup *ServerGroup

	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// Server is the name of the server which handles this request.
	Server ServerName

	// Host is the lowercased, non-FQDN version of the hostname from the
	// question of the request.
	Host string

	// ID is the unique ID of the request.  It is resurfaced here to optimize
	// context lookups.
	ID RequestID

	// QType is the type of question for this request.
	QType dnsmsg.RRType

	// QClass is the class of question for this request.
	QClass dnsmsg.Class

	// Proto is the protocol by which this request is made.
	Proto Protocol
}

// DeviceData returns the profile and device data if any.  Either both p and d
// are nil or neither is nil.
func (ri *RequestInfo) DeviceData() (p *Profile, d *Device) {
	if r, ok := ri.DeviceResult.(*DeviceResultOK); ok {
		return r.Profile, r.Device
	}

	return nil, nil
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
