package forward

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Healthcheck Logic

// refresh is an internal method used in Refresh.  It allows to enforce the
// metrics report regardless of the upstream status change.
func (h *Handler) refresh(ctx context.Context, shouldReport bool) (err error) {
	if len(h.fallbacks) == 0 {
		log.Debug("forward: healthcheck: no fallbacks specified")

		return nil
	}

	var useFallbacks bool
	lastFailed := h.lastFailedHealthcheck.Load()
	shouldReturnToMain := time.Since(time.Unix(lastFailed, 0)) >= h.hcBackoff
	if !shouldReturnToMain {
		// Make sure that useFallbacks is left true if the main upstream is
		// still in the backoff mode.
		useFallbacks = true
		log.Debug("forward: healthcheck: in backoff, will not return to main on success")
	}

	err = h.healthcheck(ctx)
	if err != nil {
		h.lastFailedHealthcheck.Store(time.Now().Unix())
		useFallbacks = true
	}

	statusChanged := h.useFallbacks.CompareAndSwap(!useFallbacks, useFallbacks)
	if statusChanged || shouldReport {
		h.setUpstreamStatus(!useFallbacks)
	}

	return errors.Annotate(err, "forward: %w")
}

// setUpstreamStatus sets the status metrics for all upstreams depending on
// whether or not the main upstream is up.
//
// TODO(a.meshkov):  Enhance the health check mechanism to report metrics for
// each upstream separately.  See AGDNS-941.
func (h *Handler) setUpstreamStatus(isUp bool) {
	if isUp {
		log.Info("forward: healthcheck: upstream got up")
	} else {
		log.Info("forward: healthcheck: negative probe")
	}

	h.metrics.OnUpstreamStatusChanged(h.upstream, true, isUp)
	for _, fb := range h.fallbacks {
		h.metrics.OnUpstreamStatusChanged(fb, false, !isUp)
	}
}

// randomPlaceholder is the placeholder replaced with a random string in
// healthcheck domain names.
const randomPlaceholder = "${RANDOM}"

// healthcheck returns an error if the handler's main upstream is not up.
func (h *Handler) healthcheck(ctx context.Context) (err error) {
	domain := h.hcDomainTmpl
	if strings.Contains(domain, randomPlaceholder) {
		randStr := strconv.FormatUint(h.rand.Uint64(), 16)
		domain = strings.ReplaceAll(domain, randomPlaceholder, randStr)
	}

	defer func() { err = errors.Annotate(err, "healthcheck: querying %q: %w", domain) }()

	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(domain),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	resp, err := h.upstream.Exchange(ctx, req)
	if err != nil {
		return err
	} else if resp == nil {
		return ErrNoResponse
	}

	if rc := resp.Rcode; rc != dns.RcodeSuccess {
		var rcVal any
		if rcStr, ok := dns.RcodeToString[rc]; ok {
			rcVal = rcStr
		} else {
			rcVal = rc
		}

		return fmt.Errorf("non-success rcode: %v", rcVal)
	}

	return nil
}
