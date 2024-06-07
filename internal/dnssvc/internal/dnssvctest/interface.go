package dnssvctest

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/miekg/dns"
)

// Package devicesetter

// type check
var _ devicesetter.Interface = (*DeviceSetter)(nil)

// DeviceSetter is a [devicesetter.Interface] implementation for DNS service
// tests.
type DeviceSetter struct {
	OnSetDevice func(
		ctx context.Context,
		req *dns.Msg,
		ri *agd.RequestInfo,
		laddr netip.AddrPort,
	) (err error)
}

// SetDevice implements the [devicesetter.Interface] interface for
// *DeviceSetter.
func (ds *DeviceSetter) SetDevice(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
	laddr netip.AddrPort,
) (err error) {
	return ds.OnSetDevice(ctx, req, ri, laddr)
}
