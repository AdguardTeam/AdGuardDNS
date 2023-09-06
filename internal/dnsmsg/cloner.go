package dnsmsg

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdsync"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Cloner is a pool that can clone common parts of DNS messages with fewer
// allocations.
//
// TODO(a.garipov): Add ECS/OPT.
//
// TODO(a.garipov): Use.
//
// TODO(a.garipov): Consider merging into [Constructor].
type Cloner struct {
	// Top-level structures.

	msg      *agdsync.TypedPool[dns.Msg]
	question *agdsync.TypedPool[[]dns.Question]

	// Mostly-answer structures.

	a     *agdsync.TypedPool[dns.A]
	aaaa  *agdsync.TypedPool[dns.AAAA]
	cname *agdsync.TypedPool[dns.CNAME]
	ptr   *agdsync.TypedPool[dns.PTR]
	srv   *agdsync.TypedPool[dns.SRV]
	txt   *agdsync.TypedPool[dns.TXT]

	// Mostly-answer custom cloners.

	https *httpsCloner

	// Mostly-NS structures.

	soa *agdsync.TypedPool[dns.SOA]
}

// NewCloner returns a new properly initialized *Cloner.
func NewCloner() (c *Cloner) {
	return &Cloner{
		msg: agdsync.NewTypedPool(func() (v *dns.Msg) {
			return &dns.Msg{}
		}),
		question: agdsync.NewTypedPool(func() (v *[]dns.Question) {
			q := make([]dns.Question, 1)

			return &q
		}),

		a: agdsync.NewTypedPool(func() (v *dns.A) {
			return &dns.A{}
		}),
		aaaa: agdsync.NewTypedPool(func() (v *dns.AAAA) {
			return &dns.AAAA{}
		}),
		cname: agdsync.NewTypedPool(func() (v *dns.CNAME) {
			return &dns.CNAME{}
		}),
		ptr: agdsync.NewTypedPool(func() (v *dns.PTR) {
			return &dns.PTR{}
		}),
		srv: agdsync.NewTypedPool(func() (v *dns.SRV) {
			return &dns.SRV{}
		}),
		txt: agdsync.NewTypedPool(func() (v *dns.TXT) {
			return &dns.TXT{}
		}),

		https: newHTTPSCloner(),

		soa: agdsync.NewTypedPool(func() (v *dns.SOA) {
			return &dns.SOA{}
		}),
	}
}

// Clone returns a deep clone of msg.  full is true if msg was cloned entirely
// without the use of [dns.Copy].
//
// msg must have exactly one question.
//
// TODO(a.garipov): Don't require one question?
func (c *Cloner) Clone(msg *dns.Msg) (clone *dns.Msg, full bool) {
	if msg == nil {
		return nil, true
	}

	clone = c.msg.Get()

	clone.MsgHdr = msg.MsgHdr
	clone.Compress = msg.Compress

	clone.Question = *c.question.Get()
	clone.Question[0] = msg.Question[0]

	clone.Answer, full = c.appendAnswer(clone.Answer[:0], msg.Answer)

	clone.Ns = clone.Ns[:0]
	for _, orig := range msg.Ns {
		var nsClone dns.RR
		switch orig := orig.(type) {
		case *dns.SOA:
			ns := c.soa.Get()
			*ns = *orig

			nsClone = ns
		// TODO(a.garipov): Add more if necessary.
		default:
			nsClone = dns.Copy(orig)
			full = false
		}

		clone.Ns = append(clone.Ns, nsClone)
	}

	clone.Extra = clone.Extra[:0]
	for _, orig := range msg.Extra {
		var exClone dns.RR
		switch orig := orig.(type) {
		// TODO(a.garipov): Add more if necessary.
		default:
			exClone = dns.Copy(orig)
			full = false
		}

		clone.Extra = append(clone.Extra, exClone)
	}

	return clone, full
}

// appendAnswer appends deep clones of all resource recornds from original to
// clones and returns it.
func (c *Cloner) appendAnswer(clones, original []dns.RR) (res []dns.RR, full bool) {
	full = true
	for _, orig := range original {
		var ansClone dns.RR
		switch orig := orig.(type) {
		case *dns.A:
			ans := c.a.Get()
			ans.Hdr = orig.Hdr

			ans.A = append(ans.A[:0], orig.A...)

			ansClone = ans
		case *dns.AAAA:
			ans := c.aaaa.Get()
			ans.Hdr = orig.Hdr

			ans.AAAA = append(ans.AAAA[:0], orig.AAAA...)

			ansClone = ans
		case *dns.CNAME:
			ans := c.cname.Get()
			*ans = *orig

			ansClone = ans
		case *dns.HTTPS:
			var httpsFull bool
			ansClone, httpsFull = c.https.clone(orig)
			full = full && httpsFull
		case *dns.PTR:
			ans := c.ptr.Get()
			*ans = *orig

			ansClone = ans
		case *dns.SRV:
			ans := c.srv.Get()
			*ans = *orig

			ansClone = ans
		case *dns.TXT:
			ans := c.txt.Get()
			ans.Hdr = orig.Hdr

			ans.Txt = append(ans.Txt[:0], orig.Txt...)

			ansClone = ans
		default:
			ansClone = dns.Copy(orig)
			full = false
		}

		clones = append(clones, ansClone)
	}

	return clones, full
}

// Put returns structures from msg into c's pools.  Neither msg nor any of its
// parts must not be used after this.
//
// msg must have exactly one question.
//
// TODO(a.garipov): Don't require one question?
func (c *Cloner) Put(msg *dns.Msg) {
	if msg == nil {
		return
	}

	c.putAnswers(msg.Answer)

	for _, ns := range msg.Ns {
		switch ns := ns.(type) {
		case *dns.SOA:
			c.soa.Put(ns)
		default:
			// Go on.
		}
	}

	for _, ex := range msg.Extra {
		// TODO(a.garipov): Add OPT.
		_ = ex
	}

	c.question.Put(&msg.Question)

	c.msg.Put(msg)
}

// putAnswers returns answers into c's pools.
func (c *Cloner) putAnswers(answers []dns.RR) {
	for _, ans := range answers {
		switch ans := ans.(type) {
		case *dns.A:
			c.a.Put(ans)
		case *dns.AAAA:
			c.aaaa.Put(ans)
		case *dns.CNAME:
			c.cname.Put(ans)
		case *dns.HTTPS:
			c.https.put(ans)
		case *dns.PTR:
			c.ptr.Put(ans)
		case *dns.SRV:
			c.srv.Put(ans)
		case *dns.TXT:
			c.txt.Put(ans)
		default:
			// Go on.
		}
	}
}

// httpsCloner is a pool that can clone common parts of DNS messages of type
// HTTPS with fewer allocations.
type httpsCloner struct {
	// Top-level structures.

	rr *agdsync.TypedPool[dns.HTTPS]

	// Values.

	alpn      *agdsync.TypedPool[dns.SVCBAlpn]
	dohpath   *agdsync.TypedPool[dns.SVCBDoHPath]
	echconfig *agdsync.TypedPool[dns.SVCBECHConfig]
	ipv4hint  *agdsync.TypedPool[dns.SVCBIPv4Hint]
	ipv6hint  *agdsync.TypedPool[dns.SVCBIPv6Hint]
	local     *agdsync.TypedPool[dns.SVCBLocal]
	mandatory *agdsync.TypedPool[dns.SVCBMandatory]
	noDefALPN *agdsync.TypedPool[dns.SVCBNoDefaultAlpn]
	port      *agdsync.TypedPool[dns.SVCBPort]

	// Miscellaneous.

	ip *agdsync.TypedPool[net.IP]
}

// newHTTPSCloner returns a new properly initialized *httpsCloner.
func newHTTPSCloner() (c *httpsCloner) {
	return &httpsCloner{
		rr: agdsync.NewTypedPool(func() (v *dns.HTTPS) {
			return &dns.HTTPS{}
		}),

		alpn: agdsync.NewTypedPool(func() (v *dns.SVCBAlpn) {
			return &dns.SVCBAlpn{}
		}),
		dohpath: agdsync.NewTypedPool(func() (v *dns.SVCBDoHPath) {
			return &dns.SVCBDoHPath{}
		}),
		echconfig: agdsync.NewTypedPool(func() (v *dns.SVCBECHConfig) {
			return &dns.SVCBECHConfig{}
		}),
		ipv4hint: agdsync.NewTypedPool(func() (v *dns.SVCBIPv4Hint) {
			return &dns.SVCBIPv4Hint{}
		}),
		ipv6hint: agdsync.NewTypedPool(func() (v *dns.SVCBIPv6Hint) {
			return &dns.SVCBIPv6Hint{}
		}),
		local: agdsync.NewTypedPool(func() (v *dns.SVCBLocal) {
			return &dns.SVCBLocal{}
		}),
		mandatory: agdsync.NewTypedPool(func() (v *dns.SVCBMandatory) {
			return &dns.SVCBMandatory{}
		}),
		noDefALPN: agdsync.NewTypedPool(func() (v *dns.SVCBNoDefaultAlpn) {
			return &dns.SVCBNoDefaultAlpn{}
		}),
		port: agdsync.NewTypedPool(func() (v *dns.SVCBPort) {
			return &dns.SVCBPort{}
		}),

		ip: agdsync.NewTypedPool(func() (v *net.IP) {
			// Use the IPv6 length to increase the effectiveness of the pool.
			ip := make(net.IP, 16)

			return &ip
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

	clone.Value = clone.Value[:0]
	for _, orig := range rr.Value {
		valClone, knownKV := c.cloneKV(orig)
		if !knownKV {
			// This branch is only reached if there is a new SVCB key-value type
			// in miekg/dns.  Give up and just use their copy function.
			return dns.Copy(rr).(*dns.HTTPS), false
		}

		clone.Value = append(clone.Value, valClone)
	}

	return clone, true
}

// cloneKV returns a deep clone of orig.  full is true if orig was recognized.
func (c *httpsCloner) cloneKV(orig dns.SVCBKeyValue) (clone dns.SVCBKeyValue, known bool) {
	switch orig := orig.(type) {
	case *dns.SVCBAlpn:
		v := c.alpn.Get()

		v.Alpn = append(v.Alpn[:0], orig.Alpn...)

		clone = v
	case *dns.SVCBDoHPath:
		v := c.dohpath.Get()
		*v = *orig

		clone = v
	case *dns.SVCBECHConfig:
		v := c.echconfig.Get()

		v.ECH = append(v.ECH[:0], orig.ECH...)

		clone = v
	case *dns.SVCBIPv4Hint:
		v := c.ipv4hint.Get()

		v.Hint = c.appendIPs(v.Hint[:0], orig.Hint)

		clone = v
	case *dns.SVCBIPv6Hint:
		v := c.ipv6hint.Get()

		v.Hint = c.appendIPs(v.Hint[:0], orig.Hint)

		clone = v
	case *dns.SVCBLocal:
		v := c.local.Get()
		v.KeyCode = orig.KeyCode

		v.Data = append(v.Data[:0], orig.Data...)

		clone = v
	case *dns.SVCBMandatory:
		v := c.mandatory.Get()

		v.Code = append(v.Code[:0], orig.Code...)

		clone = v
	case *dns.SVCBNoDefaultAlpn:
		clone = c.noDefALPN.Get()
	case *dns.SVCBPort:
		v := c.port.Get()
		*v = *orig

		clone = v
	default:
		// This branch is only reached if there is a new SVCB key-value type
		// in miekg/dns.
		return nil, false
	}

	return clone, true
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

	// Use a single large slice and subslice it to make it easier to maintain a
	// pool of these.
	ips := *c.ip.Get()
	ips = ips[:0]

	neededCap := 0
	for _, origIP := range orig {
		neededCap += len(origIP)
	}

	ips = slices.Grow(ips, neededCap)

	hints = hints[:0]
	for _, origIP := range orig {
		ips = append(ips, origIP...)
		origLen := len(origIP)
		lastIdx := len(ips)
		hints = append(hints, ips[lastIdx-origLen:lastIdx])
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
		putIPHint(c, kv)
	case *dns.SVCBIPv6Hint:
		putIPHint(c, kv)
	case *dns.SVCBLocal:
		c.local.Put(kv)
	case *dns.SVCBMandatory:
		c.mandatory.Put(kv)
	case *dns.SVCBNoDefaultAlpn:
		c.noDefALPN.Put(kv)
	case *dns.SVCBPort:
		c.port.Put(kv)
	default:
		// This branch is only reached if there is a new SVCB key-value type
		// in miekg/dns.  Noting to do.
	}
}

// putIPHint is a generic helper that returns the structures of kv into c.
func putIPHint[T *dns.SVCBIPv4Hint | *dns.SVCBIPv6Hint](c *httpsCloner, kv T) {
	switch kv := any(kv).(type) {
	case *dns.SVCBIPv4Hint:
		// TODO(a.garipov): Put the common code above the switch when Go learns
		// about common fields between types.
		if len(kv.Hint) > 0 {
			// Assume that the array underlying these slices is a single and
			// continuous one.
			c.ip.Put(&kv.Hint[0])
		}

		c.ipv4hint.Put(kv)
	case *dns.SVCBIPv6Hint:
		// TODO(a.garipov): Put the common code above the switch when Go learns
		// about common fields between types.
		if len(kv.Hint) > 0 {
			// Assume that the array underlying these slices is a single and
			// continuous one.
			c.ip.Put(&kv.Hint[0])
		}

		c.ipv6hint.Put(kv)
	default:
		// Must not happen, because there is a strict type parameter above.
		panic(fmt.Errorf("bad type %T", kv))
	}
}
