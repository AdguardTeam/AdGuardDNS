/*
Package forward implements a [dnsserver.Handler] that forwards DNS queries to
the specified DNS server.

The easiest way to use it is to create a new handler using NewHandler and then
use it in your DNS server:

	conf.Handler = forward.NewHandler(&forward.HandlerConfig{
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort("94.140.14.140:53"),
			Timeout: 5 * time.Second,
		}},
		FallbackAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort("1.1.1.1:53"),
			Timeout: 5 * time.Second,
		}},
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
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/exp/rand"
)

// Handler is a struct that implements [dnsserver.Handler] and forwards DNS
// queries to the specified upstreams.  It also implements [io.Closer], allowing
// resource reuse.
type Handler struct {
	// metrics is a listener for the handler events.
	metrics MetricsListener

	// rand is a random-number generator that is not cryptographically secure
	// and is used for randomized upstream selection and other non-sensitive
	// tasks.
	rand *rand.Rand

	// activeUpstreamsMu protects activeUpstreams.
	activeUpstreamsMu *sync.RWMutex

	// hcDomainTmpl is the template for domains used to perform healthcheck
	// requests.
	hcDomainTmpl string

	// upstreams is a list of all upstreams where this handler can forward DNS
	// queries with its last failed healthcheck timestamps.
	upstreams []*upstreamStatus

	// activeUpstreams is a list of active upstreams where this handler forwards
	// DNS queries.  This slice is updated by healthcheck mechanics.
	activeUpstreams []Upstream

	// fallbacks is a list of fallback DNS servers.
	fallbacks []Upstream

	// hcBackoffTime specifies the delay before returning to the main upstream
	// after failed healthcheck probe.
	hcBackoff time.Duration
}

// upstreamStatus contains upstream with its last failed healthcheck time.
type upstreamStatus struct {
	// upstream is an upstream where the handler can forward DNS queries.
	upstream Upstream

	// lastFailedHealthcheck contains the time of the last failed healthcheck
	// or zero if the last healthcheck succeeded.
	lastFailedHealthcheck time.Time
}

// ErrNoResponse is returned from Handler's methods when the desired response
// isn't received and no incidental errors occurred.  In theory, this must not
// happen, but we prefer to return an error instead of panicking.
const ErrNoResponse = errors.Error("no response")

// HandlerConfig is the configuration structure for [NewHandler].
type HandlerConfig struct {
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

	// UpstreamsAddresses is a list of upstream configurations of the main
	// upstreams where the handler forwards all DNS queries.  Items must no be
	// nil.
	UpstreamsAddresses []*UpstreamPlainConfig

	// FallbackAddresses are the optional fallback upstream configurations.  A
	// fallback server is used either the main upstream returns an error or when
	// the main upstream returns a SERVFAIL response.
	FallbackAddresses []*UpstreamPlainConfig

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
		rand:              rand.New(&rand.LockedSource{}),
		activeUpstreamsMu: &sync.RWMutex{},
		hcDomainTmpl:      c.HealthcheckDomainTmpl,
		hcBackoff:         c.HealthcheckBackoffDuration,
	}

	h.rand.Seed(uint64(time.Now().UnixNano()))

	if l := c.MetricsListener; l != nil {
		h.metrics = l
	} else {
		h.metrics = &EmptyMetricsListener{}
	}

	h.upstreams = make([]*upstreamStatus, 0, len(c.UpstreamsAddresses))
	h.activeUpstreams = make([]Upstream, 0, len(c.UpstreamsAddresses))
	for _, upsConf := range c.UpstreamsAddresses {
		u := NewUpstreamPlain(upsConf)
		h.activeUpstreams = append(h.activeUpstreams, u)
		h.upstreams = append(h.upstreams, &upstreamStatus{
			upstream:              u,
			lastFailedHealthcheck: time.Time{},
		})
	}

	h.fallbacks = make([]Upstream, 0, len(c.FallbackAddresses))
	for _, upsConf := range c.FallbackAddresses {
		h.fallbacks = append(h.fallbacks, NewUpstreamPlain(upsConf))
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
	errs := make([]error, 0, len(h.upstreams)+len(h.fallbacks))

	for _, u := range h.upstreams {
		errs = append(errs, u.upstream.Close())
	}

	for _, f := range h.fallbacks {
		errs = append(errs, f.Close())
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("closing forward handler: %w", err)
	}

	return nil
}

// type check
var _ dnsserver.Handler = &Handler{}

// ServeDNS implements the [dnsserver.Handler] interface for *Handler.
func (h *Handler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	var ups, fallbackUps Upstream
	defer func() { err = annotate(err, ups, fallbackUps) }()

	ups = h.pickActiveUpstream()
	useFallbacks := ups == nil

	var resp *dns.Msg
	if !useFallbacks {
		resp, err = h.exchange(ctx, ups, req)

		var netErr net.Error
		// Network error means that something is wrong with the upstream, we
		// definitely should use the fallback.
		useFallbacks = err != nil && errors.As(err, &netErr)
	}

	if useFallbacks && len(h.fallbacks) > 0 {
		i := h.rand.Intn(len(h.fallbacks))
		fallbackUps = h.fallbacks[i]
		resp, err = h.exchange(ctx, fallbackUps, req)
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
	nw := NetworkAny
	defer func() {
		h.metrics.OnForwardRequest(ctx, u, req, resp, nw, startTime, err)
	}()

	resp, nw, err = u.Exchange(ctx, req)

	return resp, err
}

// Refresh implements the [agdservice.Refresher] interface for *Handler.
//
// It checks the accessibility of main upstreams and updates handler's list of
// active upstreams.  In case all main upstreams are down, it returns an error
// and when all requests are redirected to the fallbacks.  When any of the main
// upstreams is detected to be up again, requests are redirected back to the
// main upstreams.
func (h *Handler) Refresh(ctx context.Context) (err error) {
	// TODO(a.garipov):  Use slog.
	log.Debug("upstream_healthcheck_refresh: started")
	defer log.Debug("upstream_healthcheck_refresh: finished")

	return h.refresh(ctx, false)
}

// pickActiveUpstream returns an active upstream randomly picked from the slice
// of active main upstream servers.  Returns nil when active upstreams list is
// empty and fallbacks should be used.
func (h *Handler) pickActiveUpstream() (u Upstream) {
	h.activeUpstreamsMu.RLock()
	defer h.activeUpstreamsMu.RUnlock()

	if len(h.activeUpstreams) == 0 {
		return nil
	}

	i := h.rand.Intn(len(h.activeUpstreams))

	return h.activeUpstreams[i]
}
