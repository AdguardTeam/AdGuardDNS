package dnsmsg

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// Cloner is a pool that can clone common parts of DNS messages with fewer
// allocations.
//
// TODO(a.garipov): Use in filtering when cloning a
// [filter.ResultModifiedResponse] message.
//
// TODO(a.garipov): Use in [Constructor].
type Cloner struct {
	// Statistics.

	stat ClonerStat

	// Top-level structures.

	msg *syncutil.Pool[dns.Msg]

	// Mostly-answer structures.

	a     *syncutil.Pool[dns.A]
	aaaa  *syncutil.Pool[dns.AAAA]
	cname *syncutil.Pool[dns.CNAME]
	mx    *syncutil.Pool[dns.MX]
	ptr   *syncutil.Pool[dns.PTR]
	srv   *syncutil.Pool[dns.SRV]
	txt   *syncutil.Pool[dns.TXT]

	// Mostly-answer custom cloners.

	https *httpsCloner

	// Mostly-NS structures.

	soa *syncutil.Pool[dns.SOA]

	// Mostly-extra custom cloners.

	opt *optCloner
}

// NewCloner returns a new properly initialized *Cloner.
func NewCloner(stat ClonerStat) (c *Cloner) {
	return &Cloner{
		stat: stat,

		msg: syncutil.NewPool(func() (v *dns.Msg) {
			return &dns.Msg{
				// Allocate the question, since pretty much all DNS messages
				// that are processed by DNS require exactly one.
				Question: make([]dns.Question, 1),
			}
		}),

		a: syncutil.NewPool(func() (v *dns.A) {
			return &dns.A{}
		}),
		aaaa: syncutil.NewPool(func() (v *dns.AAAA) {
			return &dns.AAAA{}
		}),
		cname: syncutil.NewPool(func() (v *dns.CNAME) {
			return &dns.CNAME{}
		}),
		mx: syncutil.NewPool(func() (v *dns.MX) {
			return &dns.MX{}
		}),
		ptr: syncutil.NewPool(func() (v *dns.PTR) {
			return &dns.PTR{}
		}),
		srv: syncutil.NewPool(func() (v *dns.SRV) {
			return &dns.SRV{}
		}),
		txt: syncutil.NewPool(func() (v *dns.TXT) {
			return &dns.TXT{}
		}),

		https: newHTTPSCloner(),

		soa: syncutil.NewPool(func() (v *dns.SOA) {
			return &dns.SOA{}
		}),

		opt: newOPTCloner(),
	}
}

// Clone returns a deep clone of msg.
func (c *Cloner) Clone(msg *dns.Msg) (clone *dns.Msg) {
	if msg == nil {
		return nil
	}

	clone = c.msg.Get()

	clone.MsgHdr = msg.MsgHdr
	clone.Compress = msg.Compress

	clone.Question = appendIfNotNil(clone.Question[:0], msg.Question)

	var ansFull, nsFull, exFull bool
	clone.Answer, ansFull = c.appendAnswer(clone.Answer[:0], msg.Answer)
	clone.Ns, nsFull = c.appendNS(clone.Ns[:0], msg.Ns)
	clone.Extra, exFull = c.appendExtra(clone.Extra[:0], msg.Extra)

	c.stat.OnClone(ansFull && nsFull && exFull)

	return clone
}

// appendAnswer appends deep clones of all resource records from original to
// clones and returns it.
//
// TODO(a.garipov): Consider ways of DRY'ing and merging with [Cloner.appendNS]
// and [Cloner.appendExtra].
func (c *Cloner) appendAnswer(clones, original []dns.RR) (res []dns.RR, full bool) {
	if original == nil {
		// TODO(a.garipov): This loses the RR slice in the message from the
		// pool.  Consider ways of mitigating that.
		return nil, true
	}

	full = true
	for _, orig := range original {
		ansClone, ansFull := c.cloneAnswerRR(orig)
		clones = append(clones, ansClone)
		full = full && ansFull
	}

	return clones, full
}

// cloneAnswerRR returns a deep clone of orig.  full is true if orig was
// recognized.
func (c *Cloner) cloneAnswerRR(orig dns.RR) (clone dns.RR, full bool) {
	switch orig := orig.(type) {
	case *dns.A:
		clone = newANetIP(c, orig.A)
	case *dns.AAAA:
		clone = newAAAANetIP(c, orig.AAAA)
	case *dns.CNAME:
		clone = newCNAME(c, orig.Target)
	case *dns.HTTPS:
		return c.https.clone(orig)
	case *dns.MX:
		clone = newMX(c, orig.Mx, orig.Preference)
	case *dns.PTR:
		clone = newPTR(c, orig.Ptr)
	case *dns.SRV:
		clone = newSRV(c, orig.Target, orig.Priority, orig.Weight, orig.Port)
	case *dns.TXT:
		clone = newTXT(c, orig.Txt)
	default:
		return dns.Copy(orig), false
	}

	*clone.Header() = *orig.Header()

	return clone, true
}

// appendNS appends deep clones of all resource records from original to
// clones and returns it.
func (c *Cloner) appendNS(clones, original []dns.RR) (res []dns.RR, full bool) {
	if original == nil {
		// TODO(a.garipov): This loses the RR slice in the message from the
		// pool.  Consider ways of mitigating that.
		return nil, true
	}

	full = true
	for _, orig := range original {
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

		clones = append(clones, nsClone)
	}

	return clones, full
}

// appendExtra appends deep clones of all resource records from original to
// clones and returns it.
func (c *Cloner) appendExtra(clones, original []dns.RR) (res []dns.RR, full bool) {
	if original == nil {
		// TODO(a.garipov): This loses the RR slice in the message from the
		// pool.  Consider ways of mitigating that.
		return nil, true
	}

	full = true
	for _, orig := range original {
		var exClone dns.RR
		switch orig := orig.(type) {
		case *dns.OPT:
			var optFull bool
			exClone, optFull = c.opt.clone(orig)
			full = full && optFull
		// TODO(a.garipov): Add more if necessary.
		default:
			exClone = dns.Copy(orig)
			full = false
		}

		clones = append(clones, exClone)
	}

	return clones, full
}

// type check
var _ dnsserver.Disposer = (*Cloner)(nil)

// Dispose implements the [dnsserver.Disposer] interface for *Cloner.  It
// returns structures from resp into c's pools.  Neither resp nor any of its
// parts must be used after this.
func (c *Cloner) Dispose(resp *dns.Msg) {
	if resp == nil {
		return
	}

	c.putAnswers(resp.Answer)

	for _, ns := range resp.Ns {
		switch ns := ns.(type) {
		case *dns.SOA:
			c.soa.Put(ns)
		default:
			// Go on.
		}
	}

	for _, ex := range resp.Extra {
		switch ex := ex.(type) {
		case *dns.OPT:
			c.opt.put(ex)
		default:
			// Go on.
		}
	}

	c.msg.Put(resp)
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
		case *dns.MX:
			c.mx.Put(ans)
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
