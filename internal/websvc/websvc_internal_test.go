package websvc

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/errors"
)

// LocalAddrs returns the local addresses of the servers in group g.  Addrs may
// contain nils.
func (svc *Service) LocalAddrs(g ServerGroup) (addrs []net.Addr) {
	switch g {
	case ServerGroupAdultBlockingPage:
		return serverAddrs(svc.adultBlocking)
	case ServerGroupGeneralBlockingPage:
		return serverAddrs(svc.generalBlocking)
	case ServerGroupLinkedIP:
		return serverAddrs(svc.linkedIP)
	case ServerGroupNonDoH:
		return serverAddrs(svc.nonDoH)
	case ServerGroupSafeBrowsingPage:
		return serverAddrs(svc.safeBrowsing)
	default:
		panic(fmt.Errorf("server group: %w: %q", errors.ErrBadEnumValue, g))
	}
}

// serverAddrs collects the addresses of the servers.
func serverAddrs(srvs []*server) (addrs []net.Addr) {
	for _, s := range srvs {
		addrs = append(addrs, s.localAddr())
	}

	return addrs
}
