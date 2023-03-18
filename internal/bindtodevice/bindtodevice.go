// Package bindtodevice contains an implementation of the [netext.ListenConfig]
// interface that uses Linux's SO_BINDTODEVICE socket option to be able to bind
// to a device.
//
// TODO(a.garipov): Finish the package.  The current plan is to eventually have
// something like this:
//
//	mgr, err := bindtodevice.New()
//	err := mgr.Add("wlp3s0_plain_dns", "wlp3s0", 53)
//	subnet := netip.MustParsePrefix("1.2.3.0/24")
//	lc, err := mgr.ListenConfig("wlp3s0_plain_dns", subnet)
//	err := mgr.Start()
//
// Approximate YAML configuration example:
//
//	'interface_listeners':
//	    # Put listeners into a list so that there is space for future additional
//	    # settings, such as timeouts and buffer sizes.
//	    'list':
//	        'iface0_plain_dns':
//	            'interface': 'iface0'
//	            'port': 53
//	        'iface0_plain_dns_secondary':
//	            'interface': 'iface0'
//	            'port': 5353
//	        # …
//	# …
//	'server_groups':
//	    # …
//	    'servers':
//	      - 'name': 'default_dns'
//	        # …
//	        bind_interfaces:
//	          - 'id': 'iface0_plain_dns'
//	            'subnet': '1.2.3.0/24'
//	          - 'id': 'iface0_plain_dns_secondary'
//	            'subnet': '1.2.3.0/24'
package bindtodevice

import (
	"fmt"
	"net"
)

// ID is the unique identifier of an interface listener.
type ID string

// unit is a convenient alias for struct{}.
type unit = struct{}

// Convenient constants containing type names for error reporting using
// [wrapConnError].
const (
	tnChanPConn = "chanPacketConn"
	tnChanLsnr  = "chanListener"
)

// wrapConnError is a helper for creating informative errors.
func wrapConnError(typeName, methodName string, laddr net.Addr, err error) (wrapped error) {
	return fmt.Errorf("bindtodevice: %s %s: %s: %w", typeName, laddr, methodName, err)
}
