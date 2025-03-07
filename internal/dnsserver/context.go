package dnsserver

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// ctxKey is the type for context keys.
type ctxKey int

const (
	ctxKeyServerInfo ctxKey = iota
	ctxKeyRequestInfo
)

// type check
var _ fmt.Stringer = ctxKey(0)

// String implements the [fmt.Stringer] interface for ctxKey.
func (k ctxKey) String() (s string) {
	switch k {
	case ctxKeyServerInfo:
		return "dnsserver.ctxKeyServerInfo"
	case ctxKeyRequestInfo:
		return "dnsserver.ctxKeyRequestInfo"
	default:
		panic(fmt.Errorf("bad ctx key value %d", k))
	}
}

// ServerInfo is a structure that contains basic server information.  It is
// attached to every context.Context created inside dnsserver.
type ServerInfo struct {
	// Name is the name of the server (Server.Name).
	Name string

	// Addr is the address that the server is configured to listen on.
	Addr string

	// Proto is the protocol of the server (Server.Proto).
	Proto Protocol
}

// ContextWithServerInfo attaches ServerInfo to the specified context.  s should
// not be nil.
func ContextWithServerInfo(parent context.Context, si *ServerInfo) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyServerInfo, si)
}

// ServerInfoFromContext gets ServerInfo attached to the context.
func ServerInfoFromContext(ctx context.Context) (si *ServerInfo, found bool) {
	v := ctx.Value(ctxKeyServerInfo)
	if v == nil {
		return nil, false
	}

	ri, ok := v.(*ServerInfo)
	if !ok {
		panicBadType(ctxKeyServerInfo, v)
	}

	return ri, true
}

// MustServerInfoFromContext gets ServerInfo attached to the context and panics
// if it is not found.
func MustServerInfoFromContext(ctx context.Context) (si *ServerInfo) {
	si, found := ServerInfoFromContext(ctx)
	if !found {
		panic("server info not found in the context")
	}

	return si
}

// RequestInfo is a structure that contains basic request information.  It is
// attached to every context.Context linked to processing a DNS request.
type RequestInfo struct {
	// URL is the request URL.  It is set only if the protocol of the server is
	// DoH.
	URL *url.URL

	// Userinfo is the userinfo from the basic authentication header.  It is set
	// only if the protocol of the server is DoH.
	Userinfo *url.Userinfo

	// StartTime is the request's start time.  It's never zero value.
	StartTime time.Time

	// TLSServerName is the original, non-lowercased server name field of the
	// client's TLS hello request.  It is set only if the protocol of the server
	// is either DoQ, DoT or DoH.
	//
	// TODO(ameshkov): use r.TLS with DoH3 (see addRequestInfo).
	TLSServerName string
}

// ContextWithRequestInfo attaches RequestInfo to the specified context.  ri
// should not be nil.
func ContextWithRequestInfo(parent context.Context, ri *RequestInfo) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyRequestInfo, ri)
}

// RequestInfoFromContext gets RequestInfo from the specified context.
func RequestInfoFromContext(ctx context.Context) (ri *RequestInfo, found bool) {
	v := ctx.Value(ctxKeyRequestInfo)
	if v == nil {
		return nil, false
	}

	ri, ok := v.(*RequestInfo)
	if !ok {
		panicBadType(ctxKeyRequestInfo, v)
	}

	return ri, true
}

// MustRequestInfoFromContext gets RequestInfo attached to the context and
// panics if it is not found.
func MustRequestInfoFromContext(ctx context.Context) (ri *RequestInfo) {
	ri, found := RequestInfoFromContext(ctx)
	if !found {
		panic("request info not found in the context")
	}

	return ri
}

// panicBadType is a helper that panics with a message about the context key and
// the expected type.
func panicBadType(key ctxKey, v any) {
	panic(fmt.Errorf("bad type for %s: %T(%[2]v)", key, v))
}
