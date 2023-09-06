package bindtodevice

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/golibs/netutil"
)

// NetInterface represents a network interface (aka device).
//
// TODO(a.garipov): Consider moving this and InterfaceStorage to netutil.
type NetInterface interface {
	Subnets() (subnets []netip.Prefix, err error)
}

// type check
var _ NetInterface = osInterface{}

// osInterface is a wrapper around [*net.Interface] that implements the
// [NetInterface] interface.
type osInterface struct {
	iface *net.Interface
}

// Subnets implements the [NetInterface] interface for osInterface.
func (osIface osInterface) Subnets() (subnets []netip.Prefix, err error) {
	name := osIface.iface.Name
	ifaceAddrs, err := osIface.iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("getting addrs for interface %s: %w", name, err)
	}

	subnets = make([]netip.Prefix, 0, len(ifaceAddrs))
	for _, addr := range ifaceAddrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("addr for interface %s is %T, not *net.IPNet", name, addr)
		}

		var subnet netip.Prefix
		subnet, err = netutil.IPNetToPrefixNoMapped(ipNet)
		if err != nil {
			return nil, fmt.Errorf("converting addr for interface %s: %w", name, err)
		}

		subnets = append(subnets, subnet)
	}

	return subnets, nil
}

// InterfaceStorage is the interface for storages of network interfaces (aka
// devices).  Its main implementation is [DefaultInterfaceStorage].
type InterfaceStorage interface {
	InterfaceByName(name string) (iface NetInterface, err error)
}

// type check
var _ InterfaceStorage = DefaultInterfaceStorage{}

// DefaultInterfaceStorage is the storage that uses the OS's network interfaces.
type DefaultInterfaceStorage struct{}

// InterfaceByName implements the [InterfaceStorage] interface for
// DefaultInterfaceStorage.
func (DefaultInterfaceStorage) InterfaceByName(name string) (iface NetInterface, err error) {
	netIface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", name, err)
	}

	return &osInterface{
		iface: netIface,
	}, nil
}
