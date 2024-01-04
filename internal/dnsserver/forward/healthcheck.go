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

// refresh is an internal method used in Refresh.  It allows to enforce the
// metrics report regardless of the upstream status change.
func (h *Handler) refresh(ctx context.Context, mustReport bool) (err error) {
	if len(h.fallbacks) == 0 {
		log.Debug("forward: healthcheck: no fallbacks specified")

		return nil
	}

	err = h.healthcheck(ctx, mustReport)

	// Set the status metrics for fallbacks depending on whether or not all main
	// upstream are up.
	//
	// TODO(a.meshkov): Enhance the health check mechanism to report metrics for
	// each fallback separately.  See AGDNS-941.
	for _, fb := range h.fallbacks {
		h.metrics.OnUpstreamStatusChanged(fb, false, err != nil)
	}

	return errors.Annotate(err, "forward: %w")
}

// randomPlaceholder is the placeholder replaced with a random string in
// healthcheck domain names.
const randomPlaceholder = "${RANDOM}"

// healthcheck returns an error if all of handler's main upstreams are down.
// Updates handler's activeUpstreams slice.
func (h *Handler) healthcheck(ctx context.Context, mustReport bool) (err error) {
	domain := h.hcDomainTmpl
	if strings.Contains(domain, randomPlaceholder) {
		randStr := strconv.FormatUint(h.rand.Uint64(), 16)
		domain = strings.ReplaceAll(domain, randomPlaceholder, randStr)
	}

	defer func() { err = errors.Annotate(err, "healthcheck: querying %q: %w", domain) }()

	req := newProbeReq(domain)

	var activeUps []Upstream
	var errs []error
	for _, status := range h.upstreams {
		inBackoff, ckErr := h.healthcheckUpstream(ctx, status, req, mustReport)
		if inBackoff {
			continue
		} else if ckErr != nil {
			errs = append(errs, ckErr)
		} else {
			activeUps = append(activeUps, status.upstream)
		}
	}

	h.activeUpstreamsMu.Lock()
	defer h.activeUpstreamsMu.Unlock()

	h.activeUpstreams = activeUps

	if len(activeUps) == 0 {
		errs = append(errs, errors.Error("all main upstreams are down"))

		return errors.Join(errs...)
	}

	return nil
}

// newProbeReq returns a new request message for given domain.
func newProbeReq(domain string) (req *dns.Msg) {
	return &dns.Msg{
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
}

// healthcheckUpstream returns an error if the upstream is down, sets last
// failed healthcheck timestamp and updates metrics for given upstream.
func (h *Handler) healthcheckUpstream(
	ctx context.Context,
	upsStatus *upstreamStatus,
	req *dns.Msg,
	mustReport bool,
) (inBackoff bool, err error) {
	lastFailed := upsStatus.lastFailedHealthcheck
	ups := upsStatus.upstream

	if time.Since(lastFailed) < h.hcBackoff {
		// Make sure that this main upstream is not in the backoff mode.
		log.Debug("forward: healthcheck: upstream %s: in backoff", ups)

		return true, nil
	}

	err = checkUpstream(ctx, ups, req)
	if err != nil {
		upsStatus.lastFailedHealthcheck = time.Now()
	} else {
		upsStatus.lastFailedHealthcheck = time.Time{}
	}

	h.reportChange(ups, err, lastFailed.IsZero(), mustReport)

	return false, errors.Annotate(err, "%s: upstream is down: %w", ups)
}

// reportChange updates the metrics if the status of upstream has changed or an
// update is required.  It also writes to the log if the status has changed.
func (h *Handler) reportChange(ups Upstream, err error, wasUp, mustReport bool) {
	isUp := err == nil
	if wasUp != isUp || mustReport {
		h.metrics.OnUpstreamStatusChanged(ups, true, isUp)
	}

	if wasUp == isUp {
		return
	}

	if wasUp {
		log.Error("forward: healthcheck: upstream %s: went down: %s", ups, err)
	} else {
		log.Info("forward: healthcheck: upstream %s: got up", ups)
	}
}

// checkUpstream returns an error if the given upstream is not up.
func checkUpstream(ctx context.Context, ups Upstream, req *dns.Msg) (err error) {
	resp, _, err := ups.Exchange(ctx, req)
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
