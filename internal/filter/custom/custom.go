// Package custom contains filters made from custom filtering rules of clients.
package custom

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/stringutil"
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
	// TODO(a.garipov):  Consider making a copy of [strings.Join] for
	// [filter.RuleText].
	textLen := 0
	for _, r := range f.rules {
		textLen += len(r) + len("\n")
	}

	b := &strings.Builder{}
	b.Grow(textLen)

	for _, r := range f.rules {
		stringutil.WriteToBuilder(b, string(r), "\n")
	}

	// Don't use cache for users' custom filters, because [rulelist.ResultCache]
	// doesn't take $client rules into account.
	//
	// TODO(a.garipov):  Consider adding client names to the result-cache keys.
	cache := rulelist.EmptyResultCache{}

	f.immutable = rulelist.NewImmutable(b.String(), filter.IDCustom, "", cache)

	f.logger.DebugContext(ctx, "engine compiled", "num_rules", f.immutable.RulesCount())
}

// DNSResult returns the result of applying the custom filter to the query with
// the given parameters.
func (f *Filter) DNSResult(
	ctx context.Context,
	clientIP netip.Addr,
	clientName string,
	host string,
	rrType dnsmsg.RRType,
	isAns bool,
) (r *urlfilter.DNSResult) {
	f.initOnce.Do(func() {
		f.init(ctx)
	})

	return f.immutable.DNSResult(clientIP, clientName, host, rrType, isAns)
}

// Rules implements the [filter.Custom] interface for *Filter.
func (f *Filter) Rules() (rules []filter.RuleText) { return f.rules }
