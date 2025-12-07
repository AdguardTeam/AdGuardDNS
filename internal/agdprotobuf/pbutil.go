// Package agdprotobuf contains protobuf utils.
package agdprotobuf

import (
	"fmt"
	"net/netip"
)

// ByteSlicesToIPs converts a slice of byte slices into a slice of netip.Addrs.
func ByteSlicesToIPs(data [][]byte) (ips []netip.Addr, err error) {
	if data == nil {
		return nil, nil
	}

	ips = make([]netip.Addr, 0, len(data))
	for i, ipData := range data {
		var ip netip.Addr
		err = ip.UnmarshalBinary(ipData)
		if err != nil {
			return nil, fmt.Errorf("ip at index %d: %w", i, err)
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

// IPsToByteSlices is a wrapper around [netip.Addr.MarshalBinary] that ignores the
// always-nil errors.
func IPsToByteSlices(ips []netip.Addr) (data [][]byte) {
	if ips == nil {
		return nil
	}

	data = make([][]byte, 0, len(ips))
	for _, ip := range ips {
		data = append(data, IPToBytes(ip))
	}

	return data
}

// IPToBytes is a wrapper around [netip.Addr.MarshalBinary] that ignores the
// always-nil error.
func IPToBytes(ip netip.Addr) (b []byte) {
	b, _ = ip.MarshalBinary()

	return b
}
