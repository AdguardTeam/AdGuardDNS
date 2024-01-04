package dnsmsg

import (
	"net"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// optCloner is a pool that can clone common parts of DNS messages of type OPT
// with fewer allocations.
type optCloner struct {
	// Top-level structures.

	rr *syncutil.Pool[dns.OPT]

	// Options.

	cookie *syncutil.Pool[dns.EDNS0_COOKIE]
	subnet *syncutil.Pool[dns.EDNS0_SUBNET]
}

// newOPTCloner returns a new properly initialized *optCloner.
func newOPTCloner() (c *optCloner) {
	return &optCloner{
		rr: syncutil.NewPool(func() (v *dns.OPT) {
			return &dns.OPT{}
		}),

		cookie: syncutil.NewPool(func() (v *dns.EDNS0_COOKIE) {
			return &dns.EDNS0_COOKIE{}
		}),
		subnet: syncutil.NewPool(func() (v *dns.EDNS0_SUBNET) {
			return &dns.EDNS0_SUBNET{
				// Use the IPv6 length to increase the effectiveness of the
				// pool.
				Address: make(net.IP, 16),
			}
		}),
	}
}

// clone returns a deep clone of rr.  full is true if rr was cloned entirely
// without the use of [dns.Copy].
func (c *optCloner) clone(rr *dns.OPT) (clone *dns.OPT, full bool) {
	if rr == nil {
		return nil, true
	}

	clone = c.rr.Get()

	clone.Hdr = rr.Hdr
	if rr.Option == nil {
		clone.Option = nil

		return clone, true
	}

	clone.Option = clone.Option[:0]
	for _, orig := range rr.Option {
		var optClone dns.EDNS0

		switch orig := orig.(type) {
		case *dns.EDNS0_COOKIE:
			opt := c.cookie.Get()
			*opt = *orig

			optClone = opt
		case *dns.EDNS0_SUBNET:
			opt := c.subnet.Get()
			opt.Code = orig.Code
			opt.Family = orig.Family
			opt.SourceNetmask = orig.SourceNetmask
			opt.SourceScope = orig.SourceScope

			opt.Address = append(opt.Address[:0], orig.Address...)

			optClone = opt
		// TODO(a.garipov): Add more if necessary.
		default:
			return dns.Copy(rr).(*dns.OPT), false
		}

		clone.Option = append(clone.Option, optClone)
	}

	return clone, true
}

// put returns structures from rr into c's pools.
func (c *optCloner) put(rr *dns.OPT) {
	if rr == nil {
		return
	}

	for _, opt := range rr.Option {
		switch opt := opt.(type) {
		case *dns.EDNS0_COOKIE:
			c.cookie.Put(opt)
		case *dns.EDNS0_SUBNET:
			c.subnet.Put(opt)
		default:
			// Go on.
		}
	}

	c.rr.Put(rr)
}
