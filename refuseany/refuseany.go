package refuseany

import (
	"fmt"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// ServeDNS handles the DNS request and refuses if it's an ANY request
func (p *plug) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		// google DNS, bind and others do the same
		return dns.RcodeFormatError, fmt.Errorf("got DNS request with != 1 questions")
	}

	q := r.Question[0]
	if q.Qtype == dns.TypeANY {
		state := request.Request{W: w, Req: r}
		rcode := dns.RcodeNotImplemented

		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		state.SizeAndDo(m)
		err := state.W.WriteMsg(m)
		if err != nil {
			clog.Infof("Got error %s\n", err)
			return dns.RcodeServerFailure, err
		}
		return rcode, nil
	}

	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}
