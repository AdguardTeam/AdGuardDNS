package messagetap

import (
	"net/netip"
	"time"

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
	now time.Time,
	queryMsg []byte,
	respMsg []byte,
) (msg *dnstap.Message, queryAddrPtr, respAddrPtr *[]byte) {
	msg = d.msgPool.Get()

	msg.Type = msgType

	qAddr := raddr.Addr()
	msg.SocketFamily = socketFamily(qAddr)

	queryAddrPtr = d.addrPool.Get()
	// Ignore the error, as it's always nil.
	*queryAddrPtr, _ = qAddr.WithZone("").AppendBinary((*queryAddrPtr)[:0])
	msg.QueryAddress = *queryAddrPtr

	queryPort := d.uint32Pool.Get()
	*queryPort = uint32(raddr.Port())
	msg.QueryPort = queryPort

	var (
		nowSec  *uint64
		nowNsec *uint32
	)

	if queryMsg != nil || respMsg != nil {
		nowSec = d.timeSecPool.Get()
		*nowSec = uint64(now.Unix())

		nowNsec = d.uint32Pool.Get()
		*nowNsec = uint32(now.Nanosecond())
	}

	if queryMsg != nil {
		msg.QueryTimeSec = nowSec
		msg.QueryTimeNsec = nowNsec
	}

	if respMsg != nil {
		msg.ResponseTimeSec = nowSec
		msg.ResponseTimeNsec = nowNsec
	}

	respAddr := laddr.Addr().WithZone("")
	respAddrPtr = d.addrPool.Get()
	// Ignore the error, as it's always nil.
	*respAddrPtr, _ = respAddr.AppendBinary((*respAddrPtr)[:0])
	msg.ResponseAddress = *respAddrPtr

	respPort := d.uint32Pool.Get()
	*respPort = uint32(laddr.Port())
	msg.ResponsePort = respPort

	msg.QueryMessage = queryMsg
	msg.ResponseMessage = respMsg

	return msg, queryAddrPtr, respAddrPtr
}

// socketFamily returns the DNSTap socket family for the given IP address.
func socketFamily(addr netip.Addr) (sf *dnstap.SocketFamily) {
	if addr.Is4() || addr.Is4In6() {
		return &socketFamilyInet
	}

	return &socketFamilyInet6
}
