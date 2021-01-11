package upstream

import (
	"context"
	"math/rand"

	"github.com/miekg/dns"
)

// Upstream - represents the plugin struct itself
type Upstream struct {
	main      *Proxy   // main upstream
	fallbacks []*Proxy // fallback upstreams
}

// Name implements plugin.Handler.
func (u *Upstream) Name() string { return "upstream" }

// ServeDNS implements plugin.Handler.
func (u *Upstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	ret, err := u.main.Exchange(r)

	if len(u.fallbacks) > 0 {
		fallback := false
		if isTimeout(err) {
			// Timeout error - smth is wrong with upstream, use fallback
			fallback = true
		} else if ret != nil && ret.Rcode == dns.RcodeServerFailure {
			// If the upstream is any recursor, this may mean that we
			// have a problem with access to the nameserver
			// It's safer to try the fallback.
			fallback = true
		}

		if fallback {
			// nolint - weak random number generator is okay here
			p := u.fallbacks[rand.Intn(len(u.fallbacks))]
			ret, err = p.Exchange(r)
		}
	}

	if ret != nil {
		_ = w.WriteMsg(ret)
		return 0, nil
	}

	return dns.RcodeServerFailure, err
}
