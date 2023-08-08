/*
Package forward implements a [dnsserver.Handler] that forwards DNS queries to
the specified DNS server.

The easiest way to use it is to create a new handler using NewHandler and then
use it in your DNS server:

	conf.Handler = forward.NewHandler(&forward.HandlerConfig{
		Address:           netip.MustParseAddrPort("8.8.8.8:53"),
		FallbackAddresses: []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:53"),
		},
		Timeout: 5 * time.Second,
	})
	srv := dnsserver.NewServerDNS(conf)
	err := srv.Start(context.Background())

That's it, you now have a working DNS forwarder.
*/
package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"golang.org/x/exp/rand"
)

// Handler is a struct that implements [dnsserver.Handler] and forwards DNS
// queries to the specified upstreams.  It also implements [io.Closer], allowing
// resource reuse.
type Handler struct {
	// metrics is a listener for the handler events.
	metrics MetricsListener

	// upstream is the main upstream where this handler forwards DNS queries.
	upstream Upstream

	// rand is a random-number generator that is not cryptographically secure
	// and is used for randomized upstream selection and other non-sensitive
	// tasks.
	rand *rand.Rand

	// hcDomainTmpl is the template for domains used to perform healthcheck
	// requests.
	hcDomainTmpl string

	// fallbacks is a list of fallback DNS servers.
	fallbacks []Upstream

	// lastFailedHealthcheck contains the Unix time of the last time of failed
	// healthcheck.
	lastFailedHealthcheck atomic.Int64

	// timeout specifies the query timeout for upstreams and fallbacks.
	timeout time.Duration

	// hcBackoffTime specifies the delay before returning to the main upstream
	// after failed healthcheck probe.
	hcBackoff time.Duration

	// useFallbacks is true if the main upstream server failed health check
	// probes and therefore the fallback upstream servers should be used for
	// resolving.
	useFallbacks atomic.Bool
}

// ErrNoResponse is returned from Handler's methods when the desired response
// isn't received and no incidental errors occurred.  In theory, this must not
// happen, but we prefer to return an error instead of panicking.
const ErrNoResponse = errors.Error("no response")

// HandlerConfig is the configuration structure for [NewHandler].
type HandlerConfig struct {
	// Address is the address of the main upstream to which the handler forwards
	// all DNS queries.
	Address netip.AddrPort

	// Network is the network protocol for the main upstream address.
	Network Network

	// MetricsListener is the optional listener for the handler events.  Set it
	// if you want to keep track of what the handler does and record performance
	// metrics.  If not set, EmptyMetricsListener is used.
	MetricsListener MetricsListener

	// HealthcheckDomainTmpl is the template for domains used to perform
	// healthcheck queries.  If the HealthcheckDomainTmpl contains the string
	// "${RANDOM}", all occurrences of this string are replaced with a random
	// string on every healthcheck query.  Queries to the resulting domains must
	// return a NOERROR response.
	HealthcheckDomainTmpl string

	// FallbackAddresses are the optional fallback DNS servers. A fallback
	// server is used either the main upstream returns an error or when the main
	// upstream returns a SERVFAIL response.
	FallbackAddresses []netip.AddrPort

	// Timeout is the optional query timeout for upstreams and fallbacks.  If
	// not set, there is no timeout.
	Timeout time.Duration

	// HealthcheckBackoffDuration is the healthcheck query backoff duration.  If
	// the main upstream is down, queries will not be routed back to the main
	// upstream until this time has passed.  If the healthcheck is still
	// performed, each failed check advances the backoff.
	HealthcheckBackoffDuration time.Duration

	// HealthcheckInitDuration is the time duration for initial upstream
	// healthcheck.
	HealthcheckInitDuration time.Duration
}

// NewHandler initializes a new instance of Handler.  It also performs a health
// check afterwards if c.HealthcheckInitDuration is not zero.  Note, that this
// handler only support plain DNS upstreams.  c must not be nil.
func NewHandler(c *HandlerConfig) (h *Handler) {
	h = &Handler{
		upstream: NewUpstreamPlain(&UpstreamPlainConfig{
			Network: c.Network,
			Address: c.Address,
		}),
		rand:         rand.New(&rand.LockedSource{}),
		hcDomainTmpl: c.HealthcheckDomainTmpl,
		timeout:      c.Timeout,
		hcBackoff:    c.HealthcheckBackoffDuration,
	}

	h.rand.Seed(uint64(time.Now().UnixNano()))

	if l := c.MetricsListener; l != nil {
		h.metrics = l
	} else {
		h.metrics = &EmptyMetricsListener{}
	}

	h.fallbacks = make([]Upstream, len(c.FallbackAddresses))
	for i, addr := range c.FallbackAddresses {
		h.fallbacks[i] = NewUpstreamPlain(&UpstreamPlainConfig{
			Network: NetworkAny,
			Address: addr,
		})
	}

	if c.HealthcheckInitDuration > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), c.HealthcheckInitDuration)
		defer cancel()

		// Ignore the error since it's considered non-critical and also should
		// have been logged already.
		_ = h.refresh(ctx, true)
	}

	return h
}

// type check
var _ io.Closer = &Handler{}

// Close implements the [io.Closer] interface for *Handler.
func (h *Handler) Close() (err error) {
	errs := make([]error, len(h.fallbacks)+1)
	errs[0] = h.upstream.Close()
	for i, f := range h.fallbacks {
		errs[i+1] = f.Close()
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("closing forward handler: %w", err)
	}

	return nil
}

// type check
var _ dnsserver.Handler = &Handler{}

// ServeDNS implements the dnsserver.Handler interface for *Handler.
func (h *Handler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	defer func() { err = annotate(err, h.upstream) }()

	useFallbacks := h.useFallbacks.Load()
	var resp *dns.Msg
	if !useFallbacks {
		resp, err = h.exchange(ctx, h.upstream, req)

		var netErr net.Error
		// Network error means that something is wrong with the upstream, we
		// definitely should use the fallback.
		useFallbacks = err != nil && errors.As(err, &netErr)
	}

	if useFallbacks && len(h.fallbacks) > 0 {
		i := h.rand.Intn(len(h.fallbacks))
		f := h.fallbacks[i]
		resp, err = h.exchange(ctx, f, req)
	}

	if err != nil {
		return fmt.Errorf("forwarding: %w", err)
	}

	if resp == nil {
		return ErrNoResponse
	}

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing response: %w", err)
	}

	return nil
}

// exchange sends a DNS message using the specified upstream.
func (h *Handler) exchange(
	ctx context.Context,
	u Upstream,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	startTime := time.Now()
	defer func() {
		h.metrics.OnForwardRequest(ctx, u, req, resp, startTime, err)
	}()

	if h.timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}

	return u.Exchange(ctx, req)
}

// Refresh makes sure that the main upstream is accessible.  In case the
// upstream is down, requests are redirected to fallbacks.  When the upstream is
// detected to be up again, requests are redirected back to it.
func (h *Handler) Refresh(ctx context.Context) (err error) {
	return h.refresh(ctx, false)
}
