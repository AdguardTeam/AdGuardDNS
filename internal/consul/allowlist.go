// Package consul contains types and utilities for updating data from Consul.
package consul

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/service"
)

// AllowlistUpdater is a wrapper that updates the allowlist on refresh.  It
// should be initially refreshed before use.
type AllowlistUpdater struct {
	logger    *slog.Logger
	allowlist *ratelimit.DynamicAllowlist
	http      *agdhttp.Client
	url       *url.URL
	errColl   errcoll.Interface
	metrics   Metrics
}

// AllowlistUpdaterConfig is the configuration structure for the allowlist
// updater.  All fields must not be nil.
type AllowlistUpdaterConfig struct {
	// Logger is used for logging the operation of the allowlist updater.
	Logger *slog.Logger

	// Allowlist is the allowlist to update.
	Allowlist *ratelimit.DynamicAllowlist

	// ConsulURL is the URL from which to update Allowlist.
	ConsulURL *url.URL

	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// Metrics is used to collect allowlist statistics.
	Metrics Metrics

	// Timeout is the timeout for Consul queries.
	Timeout time.Duration
}

// NewAllowlistUpdater returns a properly initialized *AllowlistUpdater.  c must
// not be nil.
func NewAllowlistUpdater(c *AllowlistUpdaterConfig) (upd *AllowlistUpdater) {
	return &AllowlistUpdater{
		logger:    c.Logger,
		allowlist: c.Allowlist,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: c.Timeout,
		}),
		url:     c.ConsulURL,
		errColl: c.ErrColl,
		metrics: c.Metrics,
	}
}

// type check
var _ service.Refresher = (*AllowlistUpdater)(nil)

// Refresh implements the [service.Refresher] interface for *AllowlistUpdater.
func (upd *AllowlistUpdater) Refresh(ctx context.Context) (err error) {
	upd.logger.InfoContext(ctx, "refresh started")
	defer upd.logger.InfoContext(ctx, "refresh finished")

	defer func() { upd.metrics.SetStatus(ctx, err) }()

	consulNets, err := upd.loadConsul(ctx)
	if err != nil {
		errcoll.Collect(ctx, upd.errColl, upd.logger, "loading consul allowlist", err)

		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	upd.logger.InfoContext(
		ctx,
		"refresh successful",
		"num_records", len(consulNets),
		"url", urlutil.RedactUserinfo(upd.url),
	)

	upd.allowlist.Update(consulNets)
	upd.metrics.SetSize(ctx, len(consulNets))

	return nil
}

// consulRecord is the structure for decoding the response from Consul.
type consulRecord struct {
	Address netip.Addr `json:"Address"`
}

// loadConsul fetches, decodes, and returns the list of IP networks from consul.
func (upd *AllowlistUpdater) loadConsul(ctx context.Context) (nets []netip.Prefix, err error) {
	defer func() { err = errors.Annotate(err, "loading allowlist nets: %w") }()

	httpResp, err := upd.http.Get(ctx, upd.url)
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
