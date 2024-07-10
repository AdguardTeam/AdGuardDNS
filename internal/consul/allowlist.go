// Package consul contains types and utilities for updating data from Consul.
package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// AllowlistRefresher is a refresh wrapper that updates the allowlist.  It
// should be initially refreshed before use.
type AllowlistRefresher struct {
	allowlist *ratelimit.DynamicAllowlist
	http      *agdhttp.Client
	url       *url.URL
	errColl   errcoll.Interface
}

// NewAllowlistRefresher returns a properly initialized *AllowlistRefresher.
func NewAllowlistRefresher(
	allowlist *ratelimit.DynamicAllowlist,
	consulURL *url.URL,
	errColl errcoll.Interface,
) (l *AllowlistRefresher) {
	return &AllowlistRefresher{
		allowlist: allowlist,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			// TODO(a.garipov): Consider making configurable.
			Timeout: 15 * time.Second,
		}),
		url:     consulURL,
		errColl: errColl,
	}
}

// type check
var _ agdservice.Refresher = (*AllowlistRefresher)(nil)

// Refresh implements the [agdservice.Refresher] interface for
// *AllowlistRefresher.
func (l *AllowlistRefresher) Refresh(ctx context.Context) (err error) {
	// TODO(a.garipov):  Use slog.
	log.Info("allowlist_refresh: started")
	defer log.Info("allowlist_refresh: finished")

	defer func() {
		metrics.ConsulAllowlistUpdateTime.SetToCurrentTime()
		metrics.SetStatusGauge(metrics.ConsulAllowlistUpdateStatus, err)
	}()

	consulNets, err := l.loadConsul(ctx)
	if err != nil {
		errcoll.Collectf(ctx, l.errColl, "allowlist_refresh: %w", err)

		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	log.Info("allowlist: loaded %d records from %s", len(consulNets), l.url)

	l.allowlist.Update(consulNets)
	metrics.ConsulAllowlistSize.Set(float64(len(consulNets)))

	return nil
}

// consulRecord is the structure for decoding the response from Consul.
type consulRecord struct {
	Address netip.Addr `json:"Address"`
}

// loadConsul fetches, decodes, and returns the list of IP networks from consul.
func (l *AllowlistRefresher) loadConsul(ctx context.Context) (nets []netip.Prefix, err error) {
	defer func() { err = errors.Annotate(err, "loading allowlist nets from %s: %w", l.url) }()

	httpResp, err := l.http.Get(ctx, l.url)
	if err != nil {
		return nil, fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	var records []consulRecord
	err = json.NewDecoder(httpResp.Body).Decode(&records)
	if err != nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("decoding: %w", err),
			httpResp,
		)
	}

	nets = make([]netip.Prefix, len(records))
	for i, r := range records {
		nets[i], err = r.Address.Prefix(r.Address.BitLen())
		if err != nil {
			// Technically should never happen with valid addresses.
			return nil, fmt.Errorf("converting addr at idx %d: err", i)
		}
	}

	return nets, nil
}
