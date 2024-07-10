package dnsmsg

import (
	"net"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// httpsCloner is a pool that can clone common parts of DNS messages of type
// HTTPS with fewer allocations.
type httpsCloner struct {
	// Top-level structures.

	rr *syncutil.Pool[dns.HTTPS]

	// Values.

	alpn      *syncutil.Pool[dns.SVCBAlpn]
	dohpath   *syncutil.Pool[dns.SVCBDoHPath]
	echconfig *syncutil.Pool[dns.SVCBECHConfig]
	ipv4hint  *syncutil.Pool[dns.SVCBIPv4Hint]
	ipv6hint  *syncutil.Pool[dns.SVCBIPv6Hint]
	local     *syncutil.Pool[dns.SVCBLocal]
	mandatory *syncutil.Pool[dns.SVCBMandatory]
	port      *syncutil.Pool[dns.SVCBPort]

	// Miscellaneous.

	ip *syncutil.Pool[[16]byte]
}

// newHTTPSCloner returns a new properly initialized *httpsCloner.
func newHTTPSCloner() (c *httpsCloner) {
	return &httpsCloner{
		rr: syncutil.NewPool(func() (v *dns.HTTPS) {
			return &dns.HTTPS{}
		}),

		alpn: syncutil.NewPool(func() (v *dns.SVCBAlpn) {
			return &dns.SVCBAlpn{}
		}),
		dohpath: syncutil.NewPool(func() (v *dns.SVCBDoHPath) {
			return &dns.SVCBDoHPath{}
		}),
		echconfig: syncutil.NewPool(func() (v *dns.SVCBECHConfig) {
			return &dns.SVCBECHConfig{}
		}),
		ipv4hint: syncutil.NewPool(func() (v *dns.SVCBIPv4Hint) {
			return &dns.SVCBIPv4Hint{}
		}),
		ipv6hint: syncutil.NewPool(func() (v *dns.SVCBIPv6Hint) {
			return &dns.SVCBIPv6Hint{}
		}),
		local: syncutil.NewPool(func() (v *dns.SVCBLocal) {
			return &dns.SVCBLocal{}
		}),
		mandatory: syncutil.NewPool(func() (v *dns.SVCBMandatory) {
			return &dns.SVCBMandatory{}
		}),
		port: syncutil.NewPool(func() (v *dns.SVCBPort) {
			return &dns.SVCBPort{}
		}),

		ip: syncutil.NewPool(func() (v *[16]byte) {
			// Use the IPv6 length to increase the effectiveness of the pool.
			return &[16]byte{}
		}),
	}
}

// clone returns a deep clone of rr.  full is true if rr was cloned entirely
// without the use of [dns.Copy].
func (c *httpsCloner) clone(rr *dns.HTTPS) (clone *dns.HTTPS, full bool) {
	if rr == nil {
		return nil, true
	}

	clone = c.rr.Get()

	clone.Hdr = rr.Hdr
	clone.Priority = rr.Priority
	clone.Target = rr.Target

	if rr.Value == nil {
		clone.Value = nil

		return clone, true
	}

	clone.Value = clone.Value[:0]
	for _, orig := range rr.Value {
		valClone := c.cloneKV(orig)
		if valClone == nil {
			// This branch is only reached if there is a new SVCB key-value type
			// in miekg/dns.  Give up and just use their copy function.
			return dns.Copy(rr).(*dns.HTTPS), false
		}

		clone.Value = append(clone.Value, valClone)
	}

	return clone, true
}

// cloneKV returns a deep clone of orig.  clone is nil if orig wasn't
// recognized.
func (c *httpsCloner) cloneKV(orig dns.SVCBKeyValue) (clone dns.SVCBKeyValue) {
	switch orig := orig.(type) {
	case *dns.SVCBAlpn:
		v := c.alpn.Get()
		v.Alpn = appendIfNotNil(v.Alpn[:0], orig.Alpn)

		clone = v
	case *dns.SVCBDoHPath:
		v := c.dohpath.Get()
		*v = *orig

		clone = v
	case *dns.SVCBECHConfig:
		v := c.echconfig.Get()
		v.ECH = appendIfNotNil(v.ECH[:0], orig.ECH)

		clone = v
	case *dns.SVCBLocal:
		v := c.local.Get()
		v.KeyCode = orig.KeyCode
		v.Data = appendIfNotNil(v.Data[:0], orig.Data)

		clone = v
	case *dns.SVCBMandatory:
		v := c.mandatory.Get()
		v.Code = appendIfNotNil(v.Code[:0], orig.Code)

		clone = v
	case *dns.SVCBPort:
		v := c.port.Get()
		*v = *orig

		clone = v
	case
		*dns.SVCBNoDefaultAlpn,
		*dns.SVCBOhttp:
		// Just use the original value since these [dns.SVCBKeyValue] types are
		// pointers to empty structures, so we're only interested in the actual
		// type.
		clone = orig
	default:
		clone = c.cloneIfHint(orig)
	}

	// This is only nil if there is a new SVCB key-value type in miekg/dns.
	return clone
}

// cloneIfHint returns a deep clone of orig if it's either an [dns.SVCBIPv4Hint]
// or [dns.SVCBIPv6Hint].  Otherwise, it returns nil.
func (c *httpsCloner) cloneIfHint(orig dns.SVCBKeyValue) (clone dns.SVCBKeyValue) {
	switch orig := orig.(type) {
	case *dns.SVCBIPv4Hint:
		v := c.ipv4hint.Get()
		v.Hint = c.appendIPs(v.Hint[:0], orig.Hint)

		return v
	case *dns.SVCBIPv6Hint:
		v := c.ipv6hint.Get()
		v.Hint = c.appendIPs(v.Hint[:0], orig.Hint)

		return v
	default:
		return nil
	}
}

// appendIPs appends the clones of IP addresses from orig to hints and returns
// the resulting slice.  clone is allocated as a single continuous slice.
func (c *httpsCloner) appendIPs(hints, orig []net.IP) (clone []net.IP) {
	if len(orig) == 0 {
		if orig == nil {
			return nil
		}

		return []net.IP{}
	}

	for _, origIP := range orig {
		ipArr := c.ip.Get()
		ip := append(ipArr[:0], origIP...)
		hints = append(hints, ip)
	}

	return hints
}

// put returns structures from rr into c's pools.
func (c *httpsCloner) put(rr *dns.HTTPS) {
	if rr == nil {
		return
	}

	for _, kv := range rr.Value {
		c.putKV(kv)
	}

	c.rr.Put(rr)
}

// putKV returns structures from kv into c's pools.
func (c *httpsCloner) putKV(kv dns.SVCBKeyValue) {
	switch kv := kv.(type) {
	case *dns.SVCBAlpn:
		c.alpn.Put(kv)
	case *dns.SVCBDoHPath:
		c.dohpath.Put(kv)
	case *dns.SVCBECHConfig:
		c.echconfig.Put(kv)
	case *dns.SVCBIPv4Hint:
		c.putIPs(kv.Hint)
		c.ipv4hint.Put(kv)
	case *dns.SVCBIPv6Hint:
		c.putIPs(kv.Hint)
		c.ipv6hint.Put(kv)
	case *dns.SVCBLocal:
		c.local.Put(kv)
	case *dns.SVCBMandatory:
		c.mandatory.Put(kv)
	case *dns.SVCBPort:
		c.port.Put(kv)
	case
		*dns.SVCBNoDefaultAlpn,
		*dns.SVCBOhttp:
		// Don't use pool for empty structures, see comment in [cloneKV].
	default:
		// This branch is only reached if there is a new SVCB key-value type
		// in miekg/dns.  Noting to do.
	}
}

// putIPs returns the underlying arrays of ips into c if possible.
func (c *httpsCloner) putIPs(ips []net.IP) {
	for _, ip := range ips {
		if cap(ip) >= 16 {
			c.ip.Put((*[16]byte)(ip[:16]))
		}
	}
}
