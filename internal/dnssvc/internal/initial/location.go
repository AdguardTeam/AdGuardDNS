package initial

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/miekg/dns"
)

// addLocation adds GeoIP location information about the client's remote address
// as well as the EDNS Client Subnet information, if there is one, to ri.  err
// is not nil only if req contains a malformed EDNS Client Subnet option.
func (mw *Middleware) addLocation(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	ri.Location = mw.locationData(ctx, ri.RemoteIP, "client")

	ecs, scope, err := dnsmsg.ECSFromMsg(req)
	if err != nil {
		return fmt.Errorf("adding ecs info: %w", err)
	} else if ecs != (netip.Prefix{}) {
		ri.ECS = &agd.ECS{
			Location: mw.locationData(ctx, ecs.Addr(), "ecs"),
			Subnet:   ecs,
			Scope:    scope,
		}
	}

	return nil
}

// locationData returns the GeoIP location information about the IP address.
// typ is the type of data being requested for error reporting and logging.
func (mw *Middleware) locationData(
	ctx context.Context,
	ip netip.Addr,
	typ string,
) (l *geoip.Location) {
	l, err := mw.geoIP.Data("", ip)
	if err != nil {
		// Consider GeoIP errors non-critical.  Report and go on.
		errcoll.Collectf(ctx, mw.errColl, "init mw: getting geoip for %s ip: %w", typ, err)
	}

	if l == nil {
		optlog.Debug2("init mw: no geoip for %s ip %s", typ, ip)
	} else {
		optlog.Debug4("init mw: found country/asn %q/%d for %s ip %s", l.Country, l.ASN, typ, ip)
	}

	return l
}
