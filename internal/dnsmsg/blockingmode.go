package dnsmsg

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/golibs/errors"
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

// BlockingModeCodec is a wrapper around a BlockingMode that implements the
// [json.Marshaler] and [json.Unmarshaler] interfaces.
type BlockingModeCodec struct {
	Mode BlockingMode
}

// Blocking mode type names.
const (
	bmTypeCustomIP = "custom_ip"
	bmTypeNullIP   = "null_ip"
	bmTypeNXDOMAIN = "nxdomain"
	bmTypeREFUSED  = "refused"
)

// type check
var _ json.Marshaler = BlockingModeCodec{}

// MarshalJSON implements the [json.Marshaler] interface for BlockingModeCodec.
func (c BlockingModeCodec) MarshalJSON() (b []byte, err error) {
	var j *blockingModeJSON
	switch m := c.Mode.(type) {
	case nil:
		return nil, errors.Error("nil blocking mode")
	case *BlockingModeCustomIP:
		j = &blockingModeJSON{
			Type: bmTypeCustomIP,
		}

		if m.IPv4.IsValid() {
			j.IPv4 = &m.IPv4
		}

		if m.IPv6.IsValid() {
			j.IPv6 = &m.IPv6
		}
	case *BlockingModeNullIP:
		j = &blockingModeJSON{
			Type: bmTypeNullIP,
		}
	case *BlockingModeNXDOMAIN:
		j = &blockingModeJSON{
			Type: bmTypeNXDOMAIN,
		}
	case *BlockingModeREFUSED:
		j = &blockingModeJSON{
			Type: bmTypeREFUSED,
		}
	default:
		return nil, fmt.Errorf("unexpected blocking mode %T(%[1]v)", m)
	}

	return json.Marshal(j)
}

// type check
var _ json.Unmarshaler = (*BlockingModeCodec)(nil)

// blockingModeJSON contains common fields for all BlockingMode JSON object
// properties.
type blockingModeJSON struct {
	IPv4 *netip.Addr `json:"ipv4,omitempty"`
	IPv6 *netip.Addr `json:"ipv6,omitempty"`
	Type string      `json:"type"`
}

// UnmarshalJSON implements the [json.Unmarshaler] interface for
// *BlockingModeCodec.
func (c *BlockingModeCodec) UnmarshalJSON(b []byte) (err error) {
	j := &blockingModeJSON{}
	err = json.Unmarshal(b, j)
	if err != nil {
		// Don't wrap the error, because it's the main JSON one.
		return err
	}

	switch t := j.Type; t {
	case bmTypeCustomIP:
		var m *BlockingModeCustomIP
		m, err = j.toCustomIP()
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}

		c.Mode = m
	case bmTypeNullIP:
		c.Mode = &BlockingModeNullIP{}
	case bmTypeNXDOMAIN:
		c.Mode = &BlockingModeNXDOMAIN{}
	case bmTypeREFUSED:
		c.Mode = &BlockingModeREFUSED{}
	default:
		return fmt.Errorf("unexpected blocking mode type %q", t)
	}

	return nil
}

// toCustomIP converts j into a correct *BlockingModeCustomIP.  j.Type should be
// [bmTypeCustomIP].
func (j *blockingModeJSON) toCustomIP() (m *BlockingModeCustomIP, err error) {
	defer func() {
		err = errors.Annotate(err, "bad options for blocking mode %q: %w", bmTypeCustomIP)
	}()

	ipv4Ptr, ipv6Ptr := j.IPv4, j.IPv6
	if ipv4Ptr == nil && ipv6Ptr == nil {
		return nil, errors.Error("ipv4 or ipv6 must be set")
	}

	m = &BlockingModeCustomIP{}
	m.IPv4, err = decodeCustomIP(ipv4Ptr, netip.Addr.Is4, "ipv4")
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	m.IPv6, err = decodeCustomIP(ipv6Ptr, netip.Addr.Is6, "ipv6")
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return m, nil
}

// decodeCustomIP is a helper that dereferences ipPtr, if it is not nil, checks
// the resulting IP address, and returns an informative error if necessary.
func decodeCustomIP(
	ipPtr *netip.Addr,
	isCorrectProto func(netip.Addr) bool,
	protoName string,
) (ip netip.Addr, err error) {
	if ipPtr == nil {
		return netip.Addr{}, nil
	}

	ip = *ipPtr
	if !isCorrectProto(ip) {
		return netip.Addr{}, fmt.Errorf("address %q is not %s", ip, protoName)
	}

	return ip, nil
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
