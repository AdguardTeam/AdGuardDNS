package websvc

import (
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// testTimeout is the common timeout for tests.
//
// TODO(a.garipov):  Make the test external and DRY with one in websvc_test.go
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
//
// TODO(a.garipov):  Make the test external and DRY with one in websvc_test.go
var testLogger = slogutil.NewDiscardLogger()

// LocalAddrs returns the local addresses of the servers in group g.  Addrs may
// contain nils.
//
// TODO(a.garipov):  Use in tests.
func (svc *Service) LocalAddrs(g serverGroup) (addrs []net.Addr) {
	switch g {
	case srvGrpAdultBlockingPage:
		return serverAddrs(svc.adultBlocking)
	case srvGrpGeneralBlockingPage:
		return serverAddrs(svc.generalBlocking)
	case srvGrpLinkedIP:
		return serverAddrs(svc.linkedIP)
	case srvGrpNonDoH:
		return serverAddrs(svc.nonDoH)
	case srvGrpSafeBrowsingPage:
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
