// Package forward implements a [dnsserver.Handler] that forwards DNS queries to
// the specified DNS server.
//
// The easiest way to use it is to create a new handler using NewHandler and
// then use it in your DNS server:
//
//	conf.Handler = forward.NewHandler(&forward.HandlerConfig{
//	    UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
//	        Network: forward.NetworkAny,
//	        Address: netip.MustParseAddrPort("94.140.14.140:53"),
//	        Timeout: 5 * time.Second,
//	    }},
//	    FallbackAddresses: []*forward.UpstreamPlainConfig{{
//	        Network: forward.NetworkAny,
//	        Address: netip.MustParseAddrPort("1.1.1.1:53"),
//	        Timeout: 5 * time.Second,
//	    }},
//	})
//	srv := dnsserver.NewServerDNS(conf)
//	err := srv.Start(context.Background())
//
// That's it, you now have a working DNS forwarder.
package forward

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/mathutil/randutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/miekg/dns"
)

// HandlerConfig is the configuration structure for [NewHandler].
type HandlerConfig struct {
	// Logger is used for logging the operation of the forwarding handler.  If
	// Logger is nil, [slog.Default] is used.
	Logger *slog.Logger

	// MetricsListener is the optional listener for the handler events.  Set it
	// if you want to keep track of what the handler does and record performance
	// metrics.  If not set, EmptyMetricsListener is used.
	MetricsListener MetricsListener

	// RandSource is used for randomized upstream selection and other
	// non-sensitive tasks.  If it is nil, [rand.ChaCha8] is used.
	RandSource rand.Source

	// Healthcheck is the handler's health checking configuration.  Nil
	// healthcheck is treated as disabled.
	Healthcheck *HealthcheckConfig

	// UpstreamsAddresses is a list of upstream configurations of the main
	// upstreams where the handler forwards all DNS queries.  Items must no be
	// nil.
	UpstreamsAddresses []*UpstreamPlainConfig

	// FallbackAddresses are the optional fallback upstream configurations.  A
	// fallback server is used either the main upstream returns an error or when
	// the main upstream returns a SERVFAIL response.
	FallbackAddresses []*UpstreamPlainConfig
}

// HealthcheckConfig is the configuration for the [Handler]'s healthcheck.
type HealthcheckConfig struct {
	// DomainTempalate is the template for domains used to perform healthcheck
	// queries.  If it contains the substring "${RANDOM}", all its occurrences
	// are replaced with a random string on every healthcheck query.  Queries to
	// the resulting domains must return a NOERROR response.
	DomainTempalate string

	// NetworkOverride is the network used for healthcheck queries.  If not
	// empty, it overrides the network type of the upstream for healthcheck
	// queries.
	NetworkOverride Network

	// BackoffDuration is the healthcheck query backoff duration.  If the main
	// upstream is down, queries will not be routed there until this time has
	// passed.  If the healthcheck is still performed, each failed check
	// advances the backoff.  If the value is not positive, the backoff is
	// disabled.
	BackoffDuration time.Duration

	// InitDuration is the time duration for initial upstream healthcheck.  The
	// initial healthcheck is performed only if it's positive.
	//
	// TODO(e.burkov):  Rename to InitTimeout.
	InitDuration time.Duration

	// Enabled enables healthcheck, if true.
	Enabled bool
}

// Handler is a struct that implements [dnsserver.Handler] and forwards DNS
// queries to the specified upstreams.  It also implements [io.Closer], allowing
// resource reuse.
//
// TODO(e.burkov):  Perhaps, healthcheck logic worths a separate type.
type Handler struct {
	// logger is used for logging the operation of the forwarding handler.
	logger *slog.Logger

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

	// hcNetworkOverride is the enforced network type used for healthcheck
	// queries, if not empty.
	hcNetworkOverride Network

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
const ErrNoResponse errors.Error = "no response"

// NewHandler initializes a new instance of Handler.  It also performs a health
// check afterwards if c.HealthcheckInitDuration is not zero.  Note, that this
// handler only support plain DNS upstreams.  c must not be nil.
func NewHandler(conf *HandlerConfig) (h *Handler) {
	src := conf.RandSource
	if src == nil {
		// Do not initialize through [cmp.Or], as the default value could panic.
		src = rand.NewChaCha8(randutil.MustNewSeed())
	}

	hcConf := conf.Healthcheck
	if hcConf == nil {
		hcConf = &HealthcheckConfig{}
	}

	h = &Handler{
		logger: cmp.Or(conf.Logger, slog.Default()),
		// #nosec G404 -- We don't need a real random, pseudorandom is enough.
		rand:              rand.New(randutil.NewLockedSource(src)),
		activeUpstreamsMu: &sync.RWMutex{},
	}

	if hcConf.Enabled {
		h.hcDomainTmpl = hcConf.DomainTempalate
		h.hcNetworkOverride = hcConf.NetworkOverride
		h.hcBackoff = hcConf.BackoffDuration
	}

	if l := conf.MetricsListener; l != nil {
		h.metrics = l
	} else {
		h.metrics = &EmptyMetricsListener{}
	}

	h.upstreams = make([]*upstreamStatus, 0, len(conf.UpstreamsAddresses))
	h.activeUpstreams = make([]Upstream, 0, len(conf.UpstreamsAddresses))
	for _, upsConf := range conf.UpstreamsAddresses {
		u := NewUpstreamPlain(upsConf)
		h.activeUpstreams = append(h.activeUpstreams, u)
		h.upstreams = append(h.upstreams, &upstreamStatus{
			upstream:              u,
			lastFailedHealthcheck: time.Time{},
		})
	}

	h.fallbacks = make([]Upstream, 0, len(conf.FallbackAddresses))
	for _, upsConf := range conf.FallbackAddresses {
		h.fallbacks = append(h.fallbacks, NewUpstreamPlain(upsConf))
	}

	if hcConf.Enabled && hcConf.InitDuration > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), hcConf.InitDuration)
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
		i := h.rand.IntN(len(h.fallbacks))
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

// type check
var _ service.Refresher = (*Handler)(nil)

// Refresh implements the [service.Refresher] interface for *Handler.  It checks
// the accessibility of main upstreams and updates handler's list of active
// upstreams.  In case all main upstreams are down, it returns an error and when
// all requests are redirected to the fallbacks.  When any of the main upstreams
// is detected to be up again, requests are redirected back to the main
// upstreams.
func (h *Handler) Refresh(ctx context.Context) (err error) {
	h.logger.Log(ctx, slogutil.LevelTrace, "healthcheck refresh started")
	defer h.logger.Log(ctx, slogutil.LevelTrace, "healthcheck refresh finished")

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

	i := h.rand.IntN(len(h.activeUpstreams))

	return h.activeUpstreams[i]
}
