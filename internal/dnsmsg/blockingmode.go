package dnsmsg

import (
	"net/netip"
)

// BlockingMode is a sum type of all possible ways to construct blocked or
// modified responses.  See the following types:
//
//   - [*BlockingModeCustomIP]
//   - [*BlockingModeNXDOMAIN]
//   - [*BlockingModeNullIP]
//   - [*BlockingModeREFUSED]
type BlockingMode interface {
	isBlockingMode()
}

// BlockingModeCustomIP makes the [dnsmsg.Constructor] return responses with
// custom IP addresses to A and AAAA requests.  For all other types of requests,
// as well as if one of the addresses isn't set, it returns a response with no
// answers (aka NODATA).
type BlockingModeCustomIP struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// isBlockingMode implements the BlockingMode interface for
// *BlockingModeCustomIP.
func (*BlockingModeCustomIP) isBlockingMode() {}

// BlockingModeNullIP makes the [dnsmsg.Constructor] return a null-IP response
// to A and AAAA requests.  For all other types of requests, it returns a
// response with no answers (aka NODATA).
type BlockingModeNullIP struct{}

// isBlockingMode implements the BlockingMode interface for *BlockingModeNullIP.
func (*BlockingModeNullIP) isBlockingMode() {}

// BlockingModeNXDOMAIN makes the [dnsmsg.Constructor] return responses with
// code NXDOMAIN.
type BlockingModeNXDOMAIN struct{}

// isBlockingMode implements the BlockingMode interface for
// *BlockingModeNXDOMAIN.
func (*BlockingModeNXDOMAIN) isBlockingMode() {}

// BlockingModeREFUSED makes the [dnsmsg.Constructor] return responses with
// code REFUSED.
type BlockingModeREFUSED struct{}

// isBlockingMode implements the BlockingMode interface for
// *BlockingModeREFUSED.
func (*BlockingModeREFUSED) isBlockingMode() {}
