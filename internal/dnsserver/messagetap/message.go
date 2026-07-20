package messagetap

import (
	"net/netip"

	dnstap "github.com/dnstap/golang-dnstap"
)

var (
	// dnsTapTypeMessage is the [dnstap.Dnstap] object type for messages.
	dnsTapTypeMessage = dnstap.Dnstap_MESSAGE

	// socketFamilyInet is the [dnstap.SocketFamily] for IPv4 addresses.
	socketFamilyInet = dnstap.SocketFamily_INET

	// socketFamilyInet6 is the [dnstap.SocketFamily] for IPv6 addresses.
	socketFamilyInet6 = dnstap.SocketFamily_INET6
)

// newDNSTap constructs and returns a [*dnstap.Dnstap] object from the pool.
// msg must not be nil.
func (d *DNSTap) newDNSTap(msg *dnstap.Message) (dt *dnstap.Dnstap) {
	dt = d.dtPool.Get()
	dt.Type = &dnsTapTypeMessage
	dt.Message = msg

	return dt
}

// newDNSTapMessage constructs and returns a [*dnstap.Message] message from the
// pool.  msgType must not be nil.
//
// TODO(d.kolyshev):  Reduce allocations.
func (d *DNSTap) newDNSTapMessage(
	laddr netip.AddrPort,
	raddr netip.AddrPort,
	msgType *dnstap.Message_Type,
	queryMsg []byte,
	respMsg []byte,
) (msg *dnstap.Message) {
	msg = d.msgPool.Get()

	msg.Type = msgType

	qAddr := raddr.Addr()
	msg.SocketFamily = socketFamily(qAddr)
	// Ignore the error, as it's always nil.
	msg.QueryAddress, _ = qAddr.MarshalBinary()
	msg.QueryPort = new(uint32(raddr.Port()))

	// Ignore the error, as it's always nil.
	msg.ResponseAddress, _ = laddr.Addr().MarshalBinary()
	msg.ResponsePort = new(uint32(laddr.Port()))

	msg.QueryMessage = queryMsg
	msg.ResponseMessage = respMsg

	return msg
}

// socketFamily returns the DNSTap socket family for the given IP address.
func socketFamily(addr netip.Addr) (sf *dnstap.SocketFamily) {
	if addr.Is4() || addr.Is4In6() {
		return &socketFamilyInet
	}

	return &socketFamilyInet6
}
