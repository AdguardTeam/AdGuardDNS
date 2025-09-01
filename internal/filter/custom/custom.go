// Package custom contains filters made from custom filtering rules of clients.
package custom

import (
	"context"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/urlfilter"
)

// Filter is a custom filter for a client.
type Filter struct {
	logger    *slog.Logger
	initOnce  *sync.Once
	immutable *rulelist.Immutable
	rules     []filter.RuleText
}

// Config is the configuration for a custom filter.
type Config struct {
	// Logger is used for logging the compilation of the engine.  It must not be
	// nil.
	Logger *slog.Logger

	// Rules are the rules for this custom filter.  They must not be modified
	// after calling New.
	Rules []filter.RuleText
}

// New creates a new custom filter.  c must not be nil and must be valid.
func New(c *Config) (f *Filter) {
	return &Filter{
		logger:   c.Logger,
		initOnce: &sync.Once{},
		rules:    c.Rules,
	}
}

// init initializes f.immutable.
func (f *Filter) init(ctx context.Context) {
	// Don't use cache for users' custom filters, because [rulelist.ResultCache]
	// doesn't take $client rules into account.
	//
	// TODO(a.garipov):  Consider adding client names to the result-cache keys.
	f.immutable = rulelist.NewImmutable(
		agdurlflt.RulesToBytes(f.rules),
		filter.IDCustom,
		"",
		rulelist.EmptyResultCache{},
	)

	f.logger.DebugContext(ctx, "engine compiled", "num_rules", f.immutable.RulesCount())
}

// SetURLFilterResult applies the DNS filtering engine and sets the values in
// res if any have matched.  ok is true if there is a match.  req and res must
// not be nil.
func (f *Filter) SetURLFilterResult(
	ctx context.Context,
	req *urlfilter.DNSRequest,
	res *urlfilter.DNSResult,
) (ok bool) {
	f.initOnce.Do(func() {
		f.init(ctx)
	})

	return f.immutable.SetURLFilterResult(ctx, req, res)
}

// Rules implements the [filter.Custom] interface for *Filter.
func (f *Filter) Rules() (rules []filter.RuleText) { return f.rules }
