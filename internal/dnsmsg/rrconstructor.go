package dnsmsg

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// newA constructs a new resource record of type A, optionally using c to
// allocate the structure.  callers must set rr.Hdr.  ip must be an IPv4
// address.
func newA(c *Cloner, ip netip.Addr) (rr *dns.A) {
	if c == nil {
		rr = &dns.A{}
	} else {
		rr = c.a.Get()
	}

	data := ip.As4()
	rr.A = appendIfNotNil(rr.A[:0], data[:])

	return rr
}

// newANetIP constructs a new resource record of type A, optionally using c to
// allocate the structure.  callers must set rr.Hdr.
func newANetIP(c *Cloner, ip net.IP) (rr *dns.A) {
	if c == nil {
		rr = &dns.A{}
	} else {
		rr = c.a.Get()
	}

	rr.A = appendIfNotNil(rr.A[:0], ip)

	return rr
}

// newAAAA constructs a new resource record of type AAAA, optionally using c to
// allocate the structure.  callers must set rr.Hdr.  ip must be an IPv6
// address.
func newAAAA(c *Cloner, ip netip.Addr) (rr *dns.AAAA) {
	if c == nil {
		rr = &dns.AAAA{}
	} else {
		rr = c.aaaa.Get()
	}

	data := ip.As16()
	rr.AAAA = appendIfNotNil(rr.AAAA[:0], data[:])

	return rr
}

// newAAAANetIP constructs a new resource record of type AAAA, optionally using
// c to allocate the structure.  callers must set rr.Hdr.
func newAAAANetIP(c *Cloner, ip net.IP) (rr *dns.AAAA) {
	if c == nil {
		rr = &dns.AAAA{}
	} else {
		rr = c.aaaa.Get()
	}

	rr.AAAA = appendIfNotNil(rr.AAAA[:0], ip)

	return rr
}

// newCNAME constructs a new resource record of type CNAME, optionally using c
// to allocate the structure.  callers must set rr.Hdr.
func newCNAME(c *Cloner, target string) (rr *dns.CNAME) {
	if c == nil {
		rr = &dns.CNAME{}
	} else {
		rr = c.cname.Get()
	}

	rr.Target = target

	return rr
}

// newMX constructs a new resource record of type MX, optionally using c to
// allocate the structure.  callers must set rr.Hdr.
func newMX(c *Cloner, mx string, pref uint16) (rr *dns.MX) {
	if c == nil {
		rr = &dns.MX{}
	} else {
		rr = c.mx.Get()
	}

	rr.Mx = mx
	rr.Preference = pref

	return rr
}

// newPTR constructs a new resource record of type PTR, optionally using c to
// allocate the structure.  callers must set rr.Hdr.
func newPTR(c *Cloner, ptr string) (rr *dns.PTR) {
	if c == nil {
		rr = &dns.PTR{}
	} else {
		rr = c.ptr.Get()
	}

	rr.Ptr = ptr

	return rr
}

// newSRV constructs a new resource record of type SRV, optionally using c to
// allocate the structure.  callers must set rr.Hdr.
func newSRV(c *Cloner, target string, prio, weight, port uint16) (rr *dns.SRV) {
	if c == nil {
		rr = &dns.SRV{}
	} else {
		rr = c.srv.Get()
	}

	rr.Target = target
	rr.Priority = prio
	rr.Weight = weight
	rr.Port = port

	return rr
}

// newTXT constructs a new resource record of type TXT, optionally using c to
// allocate the structure.  callers must set rr.Hdr.
func newTXT(c *Cloner, txt []string) (rr *dns.TXT) {
	if c == nil {
		rr = &dns.TXT{}
	} else {
		rr = c.txt.Get()
	}

	rr.Txt = appendIfNotNil(rr.Txt[:0], txt)

	return rr
}
