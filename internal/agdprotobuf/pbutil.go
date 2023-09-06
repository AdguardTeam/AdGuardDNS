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
