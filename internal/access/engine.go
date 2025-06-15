package access

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// blockedHostEngine is a lazy blocklist rules engine.
//
// TODO(a.garipov):  Replace/merge with [custom.Filter].
type blockedHostEngine struct {
	metrics    ProfileMetrics
	lazyEngine *urlfilter.DNSEngine
	initOnce   *sync.Once
	rules      []string
}

// newBlockedHostEngine creates a new blockedHostEngine.  mtrc must not be nil.
func newBlockedHostEngine(mtrc ProfileMetrics, rules []string) (e *blockedHostEngine) {
	return &blockedHostEngine{
		metrics:  mtrc,
		rules:    rules,
		initOnce: &sync.Once{},
	}
}

// isBlocked returns true if the req is blocked by this engine.  req must have
// exactly one question.
//
// TODO(s.chzhen):  Use config.
func (e *blockedHostEngine) isBlocked(ctx context.Context, req *dns.Msg) (blocked bool) {
	e.initOnce.Do(func() {
		// TODO(s.chzhen):  Use [timeutil.Clock].
		start := time.Now()

		e.lazyEngine = e.init()

		e.metrics.ObserveProfileInit(ctx, time.Since(start))
	})

	q := req.Question[0]
	res, matched := e.lazyEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname: agdnet.NormalizeQueryDomain(q.Name),
		DNSType:  q.Qtype,
	})

	if matched && res.NetworkRule != nil {
		return !res.NetworkRule.Whitelist
	}

	return matched
}

// init returns new properly initialized dns engine.
func (e *blockedHostEngine) init() (eng *urlfilter.DNSEngine) {
	b := &strings.Builder{}
	for _, h := range e.rules {
		stringutil.WriteToBuilder(b, strings.ToLower(h), "\n")
	}

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             blocklistFilterID,
			RulesText:      b.String(),
			IgnoreCosmetic: true,
		},
	}

	rulesStrg, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		// Should never happen, since the storage has only one list.
		panic(fmt.Errorf("unexpected access config error: %w", err))
	}

	return urlfilter.NewDNSEngine(rulesStrg)
}
