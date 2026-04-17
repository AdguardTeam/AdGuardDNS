package debugsvc

import (
	"fmt"
	"net"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
)

// LocalAddr returns the local address of the server in a handler group hd.
// addr can be nil.
func (svc *Service) LocalAddr(hg HandlerGroup) (addr net.Addr) {
	switch hg {
	case
		HandlerGroupAPI,
		HandlerGroupDNSDB,
		HandlerGroupPprof,
		HandlerGroupPrometheus:
	default:
		panic(fmt.Errorf("handler group: %w: %q", errors.ErrBadEnumValue, hg))
	}

	for _, srv := range svc.servers {
		// If there are multiple services in the Service working on the same
		// address, their names are concatenated.  Therefore, check whether the
		// server name contains the handler group name.
		if slices.Contains(stringutil.SplitTrimmed(srv.name, ";"), hg) {
			return srv.srv.LocalAddr()
		}
	}

	return nil
}
