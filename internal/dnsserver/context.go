package dnsserver

import (
	"context"
	"net/url"
	"time"
)

// Context Helpers

type ctxKey int

const (
	ctxKeyServerInfo ctxKey = iota
	ctxKeyStartTime
	ctxKeyRequestSize
	ctxKeyResponseSize
	ctxKeyClientInfo
)

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

// ContextWithServerInfo attaches ServerInfo to the specified context.
func ContextWithServerInfo(parent context.Context, s ServerInfo) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyServerInfo, s)
}

// ServerInfoFromContext gets ServerInfo attached to the context.
func ServerInfoFromContext(ctx context.Context) (s ServerInfo, found bool) {
	s, found = ctx.Value(ctxKeyServerInfo).(ServerInfo)

	return s, found
}

// MustServerInfoFromContext gets ServerInfo attached to the context and panics
// if it is not found.
func MustServerInfoFromContext(ctx context.Context) (s ServerInfo) {
	s, found := ServerInfoFromContext(ctx)
	if !found {
		panic("server info not found in the context")
	}

	return s
}

// ContextWithStartTime attaches request's start time to the specified context.
func ContextWithStartTime(parent context.Context, t time.Time) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyStartTime, t)
}

// StartTimeFromContext gets request's start time from the context.
func StartTimeFromContext(ctx context.Context) (startTime time.Time, found bool) {
	startTime, found = ctx.Value(ctxKeyStartTime).(time.Time)
	return startTime, found
}

// MustStartTimeFromContext gets request's start time from the context or panics
// if it's not found.
func MustStartTimeFromContext(ctx context.Context) (t time.Time) {
	st, found := ctx.Value(ctxKeyStartTime).(time.Time)
	if !found {
		panic("request's start time not found in the context")
	}

	return st
}

// ContextWithRequestSize attaches request's size to the specified context.
func ContextWithRequestSize(parent context.Context, size int) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyRequestSize, size)
}

// RequestSizeFromContext gets request's size from the context.
func RequestSizeFromContext(ctx context.Context) (size int, found bool) {
	size, found = ctx.Value(ctxKeyRequestSize).(int)

	return size, found
}

// ContextWithResponseSize attaches response's size to the specified context.
func ContextWithResponseSize(parent context.Context, size int) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyResponseSize, size)
}

// ResponseSizeFromContext gets response's size from the context.
func ResponseSizeFromContext(ctx context.Context) (size int, found bool) {
	size, found = ctx.Value(ctxKeyResponseSize).(int)
	return size, found
}

// ClientInfo is a structure that contains basic information about the client.
// It is attached to every context.Context created inside dnsserver.
type ClientInfo struct {
	// URL is the request URL.  It is set only if the protocol of the
	// server is DoH.
	URL *url.URL
	// TLSServerName is the server name field of the client's TLS hello
	// request.  It is set only if the protocol of the server is either DoQ
	// or DoT.  Note, that the original SNI is transformed to lower-case.
	TLSServerName string
}

// ContextWithClientInfo attaches the client information to the context.
func ContextWithClientInfo(parent context.Context, ci ClientInfo) (ctx context.Context) {
	return context.WithValue(parent, ctxKeyClientInfo, ci)
}

// ClientInfoFromContext returns the client information from the context.
func ClientInfoFromContext(ctx context.Context) (ci ClientInfo, found bool) {
	ci, found = ctx.Value(ctxKeyClientInfo).(ClientInfo)

	return ci, found
}

// MustClientInfoFromContext gets ClientInfo attached to the context and panics
// if it is not found.
func MustClientInfoFromContext(ctx context.Context) (ci ClientInfo) {
	ci, found := ClientInfoFromContext(ctx)
	if !found {
		panic("client info not found in the context")
	}

	return ci
}
