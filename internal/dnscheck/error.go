package dnscheck

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/golibs/errors"
)

// incErrMetrics increments error gauge metrics for the given src and err.
// "source" can be "dns" or "http".
func incErrMetrics(src string, err error) {
	if err == nil {
		return
	}

	var errType string
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		errType = "timeout"
	case errors.Is(err, consulkv.ErrRateLimited):
		errType = "ratelimit"
	default:
		errType = "other"
	}

	metrics.DNSCheckErrorTotal.WithLabelValues(src, errType).Inc()
}
