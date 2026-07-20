package agd

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/requestid"
)

// ctxKey is the type for all common context keys.
type ctxKey uint8

// Context key values.
const (
	ctxKeyReqInfo ctxKey = iota
)

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

	// ServerInfo contains the information about the server processing the query
	// and its server group.  It must not be nil.
	ServerInfo *RequestServerInfo

	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// Host is the lowercased, non-FQDN version of the hostname from the
	// question of the request.
	Host string

	// QType is the type of question for this request.
	QType dnsmsg.RRType

	// QClass is the class of question for this request.
	QClass dnsmsg.Class
}

// RequestServerInfo contains the information about the server and its group
// relevant to the request.
type RequestServerInfo struct {
	// GroupName is the unique name of the server group.  It must not be empty.
	GroupName ServerGroupName

	// Name is the unique name of the server.  It must not be empty.
	Name ServerName

	// DeviceDomains is the list of domain names that the server group uses to
	// detect device IDs from clients' server names.
	DeviceDomains []string

	// Protocol is the protocol by which this request is made.
	Protocol Protocol

	// ProfilesEnabled, if true, enables recognition of user devices and
	// profiles for the server group.
	ProfilesEnabled bool
}

// ServerGroupName is the name of a server group.
type ServerGroupName string

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
	v := ctx.Value(ctxKeyReqInfo)
	if v == nil {
		return nil, false
	}

	ri, ok = v.(*RequestInfo)
	if !ok {
		panic(fmt.Errorf("bad type for ctxKeyReqInfo: %T(%[1]v)", v))
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

// EnsureContextRequestID returns parent with a [requestid.ID] if it doesn't
// have one.
func EnsureContextRequestID(parent context.Context) (ctx context.Context) {
	_, ok := requestid.IDFromContext(parent)
	if !ok {
		return requestid.ContextWithRequestID(parent, requestid.New())
	}

	return parent
}
