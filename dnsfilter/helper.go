package dnsfilter

import (
	"fmt"
	"net"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// lookup host, but return answer as if it was a result of different lookup
// TODO: works only on A and AAAA, the go stdlib resolver can't do arbitrary types
func lookupReplaced(host string, question dns.Question) ([]dns.RR, error) {
	var records []dns.RR
	var res *net.Resolver // nil resolver is default resolver
	switch question.Qtype {
	case dns.TypeA:
		addrs, err := res.LookupIPAddr(context.TODO(), host)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, addr.IP.String()))
				if err != nil {
					return nil, err // fail entire request, TODO: return partial request?
				}
				records = append(records, rr)
			}
		}
	case dns.TypeAAAA:
		addrs, err := res.LookupIPAddr(context.TODO(), host)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.To4() == nil {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", question.Name, addr.IP.String()))
				if err != nil {
					return nil, err // fail entire request, TODO: return partial request?
				}
				records = append(records, rr)
			}
		}
	}
	return records, nil
}

func (p *plug) replaceHostWithValAndReply(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, host string, val string, question dns.Question) (int, error) {
	// check if it's a domain name or IP address
	addr := net.ParseIP(val)
	var records []dns.RR
	// log.Println("Will give", val, "instead of", host) // debug logging
	if addr != nil {
		// this is an IP address, return it
		result, err := dns.NewRR(fmt.Sprintf("%s %d A %s", host, p.settings.BlockedTTL, val))
		if err != nil {
			clog.Infof("Got error %s\n", err)
			return dns.RcodeServerFailure, fmt.Errorf("plugin/dnsfilter: %s", err)
		}
		records = append(records, result)
	} else {
		// this is a domain name, need to look it up
		var err error
		records, err = lookupReplaced(dns.Fqdn(val), question)
		if err != nil {
			clog.Infof("Got error %s\n", err)
			return dns.RcodeServerFailure, fmt.Errorf("plugin/dnsfilter: %s", err)
		}
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Compress = true
	m.Answer = append(m.Answer, records...)
	state := request.Request{W: w, Req: r}
	state.SizeAndDo(m)
	err := state.W.WriteMsg(m)
	if err != nil {
		clog.Infof("Got error %s\n", err)
		return dns.RcodeServerFailure, fmt.Errorf("plugin/dnsfilter: %s", err)
	}
	return dns.RcodeSuccess, nil
}

// generate SOA record that makes DNS clients cache NXdomain results
// the only value that is important is TTL in header, other values like refresh, retry, expire and minttl are irrelevant
func (p *plug) genSOA(request *dns.Msg) []dns.RR {
	zone := ""
	if len(request.Question) > 0 {
		zone = request.Question[0].Name
	}

	soa := dns.SOA{
		// values copied from verisign's nonexistent .com domain
		// their exact values are not important in our use case because they are used for domain transfers between primary/secondary DNS servers
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  86400,
		// copied from AdGuard DNS
		Ns:     "fake-for-negative-caching.adguard.com.",
		Serial: 100500,
		// rest is request-specific
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Ttl:    p.settings.BlockedTTL,
			Class:  dns.ClassINET,
		},
		Mbox: "hostmaster.", // zone will be appended later if it's not empty or "."
	}
	if soa.Hdr.Ttl == 0 {
		soa.Hdr.Ttl = p.settings.BlockedTTL
	}
	if len(zone) > 0 && zone[0] != '.' {
		soa.Mbox += zone
	}
	return []dns.RR{&soa}
}

func (p *plug) genARecord(request *dns.Msg, ip net.IP) *dns.Msg {
	resp := dns.Msg{}
	resp.SetReply(request)
	resp.Answer = append(resp.Answer, p.genAAnswer(request, ip))
	resp.RecursionAvailable = true
	resp.Compress = true
	return &resp
}

func (p *plug) genAAAARecord(request *dns.Msg, ip net.IP) *dns.Msg {
	resp := dns.Msg{}
	resp.SetReply(request)
	resp.Answer = append(resp.Answer, p.genAAAAAnswer(request, ip))
	resp.RecursionAvailable = true
	resp.Compress = true
	return &resp
}

func (p *plug) genAAnswer(req *dns.Msg, ip net.IP) *dns.A {
	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    p.settings.BlockedTTL,
		Class:  dns.ClassINET,
	}
	answer.A = ip
	return answer
}

func (p *plug) genAAAAAnswer(req *dns.Msg, ip net.IP) *dns.AAAA {
	answer := new(dns.AAAA)
	answer.Hdr = dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeAAAA,
		Ttl:    p.settings.BlockedTTL,
		Class:  dns.ClassINET,
	}
	answer.AAAA = ip
	return answer
}

func (p *plug) genNXDomain(request *dns.Msg) *dns.Msg {
	resp := dns.Msg{}
	resp.SetRcode(request, dns.RcodeNameError)
	resp.RecursionAvailable = true
	resp.Ns = p.genSOA(request)
	return &resp
}

func (p *plug) writeNXDomain(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := p.genNXDomain(r)

	state := request.Request{W: w, Req: r}
	state.SizeAndDo(m)
	err := state.W.WriteMsg(m)
	if err != nil {
		clog.Warningf("Got error %s\n", err)
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeNameError, nil
}

func (p *plug) writeBlacklistedResponse(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var reply *dns.Msg

	switch r.Question[0].Qtype {
	case dns.TypeA:
		reply = p.genARecord(r, []byte{0, 0, 0, 0})
	case dns.TypeAAAA:
		reply = p.genAAAARecord(r, net.IPv6zero)
	default:
		reply = p.genNXDomain(r)
	}

	state := request.Request{W: w, Req: r}
	state.SizeAndDo(reply)
	err := state.W.WriteMsg(reply)
	if err != nil {
		clog.Warningf("Got error %s\n", err)
		return dns.RcodeServerFailure, err
	}
	return reply.Rcode, nil
}
