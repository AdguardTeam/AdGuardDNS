// Package dnspb contains the protobuf structures for the gRPC DNS API as well
// as helpers for conversions.
//
// TODO(a.garipov):  Refactor tests and extend them.
package dnspb

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// CIDRRangeToInternal is a helper that converts a slice of CidrRange to a slice
// of [netip.Prefix].  errColl and l must not be nil.
func CIDRRangeToInternal(
	ctx context.Context,
	l *slog.Logger,
	pbCIDRs []*CidrRange,
	errColl errcoll.Interface,
) (cidrs []netip.Prefix) {
	for i, c := range pbCIDRs {
		pbAddr := c.GetAddress()
		addr, ok := netip.AddrFromSlice(pbAddr)
		if ok {
			cidrs = append(cidrs, netip.PrefixFrom(addr, int(c.Prefix)))

			continue
		}

		err := fmt.Errorf("bad cidr at index %d: %v", i, pbAddr)
		errcoll.Collect(ctx, errColl, l, "converting cidrs", err)
	}

	return cidrs
}
